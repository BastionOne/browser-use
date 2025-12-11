"""Network interception watchdog for capturing HTTP traffic via CDP."""

import asyncio
import base64
import json
from typing import TYPE_CHECKING, Any, ClassVar, Optional

from bubus import BaseEvent
from cdp_use.cdp.network import (
	RequestWillBeSentEvent,
	ResponseReceivedEvent,
	LoadingFinishedEvent,
	LoadingFailedEvent,
)
from cdp_use.cdp.target import SessionID, TargetID
from pydantic import PrivateAttr

from browser_use.browser.events import (
	BrowserLaunchEvent,
	BrowserStoppedEvent,
	TabCreatedEvent,
	TabClosedEvent,
	NavigationCompleteEvent,
)
from browser_use.browser.watchdog_base import BaseWatchdog

if TYPE_CHECKING:
	pass


class NetworkInterceptionWatchdog(BaseWatchdog):
	"""Monitors network traffic and forwards to HTTPHandler."""

	# Events this watchdog listens to (for documentation)
	LISTENS_TO: ClassVar[list[type[BaseEvent[Any]]]] = [
		BrowserLaunchEvent,
		BrowserStoppedEvent,
		TabCreatedEvent,
		TabClosedEvent,
		NavigationCompleteEvent,
	]

	# Events this watchdog emits (none currently, forwards to handler directly)
	EMITS: ClassVar[list[type[BaseEvent[Any]]]] = []

	# Private state
	_network_monitored_targets: set[str] = PrivateAttr(default_factory=set)
	_network_callback_registered: bool = PrivateAttr(default=False)
	_pending_requests: dict[str, dict[str, Any]] = PrivateAttr(default_factory=dict)  # requestId -> request data
	_pending_responses: dict[str, dict[str, Any]] = PrivateAttr(default_factory=dict)  # requestId -> response data
	_cdp_event_tasks: set[asyncio.Task] = PrivateAttr(default_factory=set)  # Track event handler tasks
	_http_handler: Any = PrivateAttr(default=None)  # HTTPHandler instance

	def set_http_handler(self, handler: Any) -> None:
		"""Set or clear the HTTP handler used to forward network events."""
		self._http_handler = handler

		if handler is None:
			# Pause interception and clear any in-flight state
			for task in list(self._cdp_event_tasks):
				if not task.done():
					task.cancel()
			self._cdp_event_tasks.clear()
			self._pending_requests.clear()
			self._pending_responses.clear()
			self._network_monitored_targets.clear()
			self.logger.debug('[NetworkInterceptionWatchdog] HTTP handler cleared, network monitoring paused')

	async def ensure_existing_targets_monitored(self) -> None:
		"""Attach network monitoring to any already-open targets."""
		if not self._http_handler:
			self.logger.debug('[NetworkInterceptionWatchdog] Cannot enable monitoring without HTTP handler')
			return

		try:
			targets = await self.browser_session._cdp_get_all_pages()
		except Exception:
			self.logger.exception('[NetworkInterceptionWatchdog] Failed to enumerate existing targets for monitoring')
			return

		target_ids = [target.get('targetId') for target in targets if target.get('targetId')]
		if not target_ids:
			self.logger.debug('[NetworkInterceptionWatchdog] No existing targets found to monitor')
			return

		self.logger.debug(
			f'[NetworkInterceptionWatchdog] Enabling network monitoring for {len(target_ids)} existing target(s)'
		)
		for target_id in target_ids:
			await self.attach_to_target(target_id)

	async def on_BrowserLaunchEvent(self, event: BrowserLaunchEvent) -> None:
		"""Handle browser launch."""
		self.logger.debug('[NetworkInterceptionWatchdog] Browser launched')

	async def on_TabCreatedEvent(self, event: TabCreatedEvent) -> None:
		"""Monitor new tabs for network traffic."""
		if event.target_id:
			await self.attach_to_target(event.target_id)

	async def on_TabClosedEvent(self, event: TabClosedEvent) -> None:
		"""Clean up when tabs are closed."""
		if event.target_id in self._network_monitored_targets:
			self._network_monitored_targets.discard(event.target_id)

	async def on_BrowserStoppedEvent(self, event: BrowserStoppedEvent) -> None:
		"""Clean up when browser stops."""
		# Cancel all CDP event handler tasks
		for task in list(self._cdp_event_tasks):
			if not task.done():
				task.cancel()
		if self._cdp_event_tasks:
			await asyncio.gather(*self._cdp_event_tasks, return_exceptions=True)
		self._cdp_event_tasks.clear()

		# Clear state
		self._network_monitored_targets.clear()
		self._pending_requests.clear()
		self._pending_responses.clear()
		self._network_callback_registered = False

	async def on_NavigationCompleteEvent(self, event: NavigationCompleteEvent) -> None:
		"""Ensure network monitoring is active after navigation."""
		if event.target_id:
			await self.attach_to_target(event.target_id)

	async def attach_to_target(self, target_id: TargetID) -> None:
		"""Set up network monitoring for a specific target."""
		if not self._http_handler:
			self.logger.debug('[NetworkInterceptionWatchdog] No HTTP handler set, skipping network monitoring')
			return

		# Skip if already monitoring this target
		if target_id in self._network_monitored_targets:
			return

		try:
			cdp_client = self.browser_session.cdp_client

			# Register global callbacks once
			if not self._network_callback_registered:
				self.logger.debug('[NetworkInterceptionWatchdog] Registering global network callbacks')

				def on_request_will_be_sent(event: RequestWillBeSentEvent, session_id: SessionID | None) -> None:
					"""Handle Network.requestWillBeSent CDP event."""
					try:
						# Look up target_id from session_id
						event_target_id = self.browser_session.get_target_id_from_session_id(session_id)
						if not event_target_id or event_target_id not in self._network_monitored_targets:
							return

						request_id = event.get('requestId')
						if not request_id:
							return

						request_data = event.get('request', {})
						url = request_data.get('url', '')

						# Check ban list early
						if self._http_handler._is_banned(url):
							return

						# Store request data with requestId as key
						self._pending_requests[request_id] = {
							'event': event,
							'target_id': event_target_id,
							'url': url,
							'method': request_data.get('method', 'GET'),
							'headers': request_data.get('headers', {}),
							'post_data': request_data.get('postData'),
						}

						# Create task to handle request
						task = asyncio.create_task(
							self._handle_request(request_id),
							name=f'net-req-{request_id[:8]}'
						)
						self._cdp_event_tasks.add(task)
						task.add_done_callback(lambda t: self._cdp_event_tasks.discard(t))

					except Exception:
						self.logger.exception('[NetworkInterceptionWatchdog] Error in on_request_will_be_sent')

				def on_response_received(event: ResponseReceivedEvent, session_id: SessionID | None) -> None:
					"""Handle Network.responseReceived CDP event."""
					try:
						event_target_id = self.browser_session.get_target_id_from_session_id(session_id)
						if not event_target_id or event_target_id not in self._network_monitored_targets:
							return

						request_id = event.get('requestId')
						if not request_id or request_id not in self._pending_requests:
							return

						# Store response metadata
						self._pending_responses[request_id] = event

					except Exception:
						self.logger.exception('[NetworkInterceptionWatchdog] Error in on_response_received')

				def on_loading_finished(event: LoadingFinishedEvent, session_id: SessionID | None) -> None:
					"""Handle Network.loadingFinished CDP event."""
					try:
						event_target_id = self.browser_session.get_target_id_from_session_id(session_id)
						if not event_target_id or event_target_id not in self._network_monitored_targets:
							return

						request_id = event.get('requestId')
						if not request_id or request_id not in self._pending_requests:
							return

						# Create task to complete the response
						task = asyncio.create_task(
							self._handle_loading_finished(request_id, session_id),
							name=f'net-resp-{request_id[:8]}'
						)
						self._cdp_event_tasks.add(task)
						task.add_done_callback(lambda t: self._cdp_event_tasks.discard(t))

					except Exception:
						self.logger.exception('[NetworkInterceptionWatchdog] Error in on_loading_finished')

				def on_loading_failed(event: LoadingFailedEvent, session_id: SessionID | None) -> None:
					"""Handle Network.loadingFailed CDP event."""
					try:
						event_target_id = self.browser_session.get_target_id_from_session_id(session_id)
						if not event_target_id or event_target_id not in self._network_monitored_targets:
							return

						request_id = event.get('requestId')
						if not request_id:
							return

						# Create task to handle failed request
						task = asyncio.create_task(
							self._handle_loading_failed(request_id, event),
							name=f'net-fail-{request_id[:8]}'
						)
						self._cdp_event_tasks.add(task)
						task.add_done_callback(lambda t: self._cdp_event_tasks.discard(t))

					except Exception:
						self.logger.exception('[NetworkInterceptionWatchdog] Error in on_loading_failed')

				# Register the callbacks
				cdp_client.register.Network.requestWillBeSent(on_request_will_be_sent)  # type: ignore[arg-type]
				cdp_client.register.Network.responseReceived(on_response_received)  # type: ignore[arg-type]
				cdp_client.register.Network.loadingFinished(on_loading_finished)  # type: ignore[arg-type]
				cdp_client.register.Network.loadingFailed(on_loading_failed)  # type: ignore[arg-type]

				self._network_callback_registered = True

			# Enable Network domain for this target
			cdp_session = await self.browser_session.get_or_create_cdp_session(target_id)
			await cdp_client.send.Network.enable(session_id=cdp_session.session_id)

			# Mark this target as monitored
			self._network_monitored_targets.add(target_id)
			self.logger.debug(f'[NetworkInterceptionWatchdog] Network monitoring enabled for target {target_id[-4:]}')

		except Exception as e:
			self.logger.warning(f'[NetworkInterceptionWatchdog] Failed to set up network monitoring for target {target_id}: {e}')

	async def _handle_request(self, request_id: str) -> None:
		"""Forward request to HTTPHandler."""
		try:
			if not self._http_handler:
				return
			request_data = self._pending_requests.get(request_id)
			if not request_data:
				return

			# Import here to avoid circular dependency
			from bupp.src.utils.httplib import HTTPRequest, HTTPRequestData

			# Parse post data if present
			post_dict: Optional[dict[str, Any]] = None
			post_data_raw = request_data.get('post_data')
			if post_data_raw and request_data['method'] in {'POST', 'PUT', 'PATCH', 'DELETE'}:
				headers_lower = {k.lower(): v for k, v in request_data['headers'].items()}
				content_type = headers_lower.get('content-type', '')
				try:
					if 'application/json' in content_type:
						post_dict = json.loads(post_data_raw)
					else:
						from bupp.src.utils.httplib import parse_post_data
						post_dict = parse_post_data(post_data_raw)
				except Exception:
					from bupp.src.utils.httplib import parse_post_data
					post_dict = parse_post_data(post_data_raw)

			# Build HTTPRequest
			http_request = HTTPRequest(
				data=HTTPRequestData(
					method=request_data['method'],
					url=request_data['url'],
					headers={k.lower(): v for k, v in request_data['headers'].items()},
					post_data=post_dict,
					redirected_from_url=None,
					redirected_to_url=None,
					is_iframe=False,
				)
			)

			# Forward to handler with requestId for correlation
			await self._http_handler.handle_request(http_request, request_id=request_id)

		except Exception:
			self.logger.exception(f'[NetworkInterceptionWatchdog] Error handling request {request_id}')

	async def _handle_loading_finished(self, request_id: str, session_id: SessionID | None) -> None:
		"""Fetch response body and forward complete request/response pair to HTTPHandler."""
		try:
			if not self._http_handler:
				return
			request_data = self._pending_requests.pop(request_id, None)
			response_event = self._pending_responses.pop(request_id, None)

			if not request_data or not response_event:
				return

			# Import here to avoid circular dependency
			from bupp.src.utils.httplib import HTTPRequest, HTTPRequestData, HTTPResponse, HTTPResponseData

			response_data = response_event.get('response', {})
			status = response_data.get('status', 0)
			headers = response_data.get('headers', {})
			headers_lower = {k.lower(): v for k, v in headers.items()}

			# Fetch response body via CDP
			body_bytes: Optional[bytes] = None
			body_error: Optional[str] = None

			try:
				cdp_client = self.browser_session.cdp_client
				body_result = await cdp_client.send.Network.getResponseBody(
					params={'requestId': request_id},
					session_id=session_id
				)
				body_str = body_result.get('body', '')
				base64_encoded = body_result.get('base64Encoded', False)

				if base64_encoded:
					body_bytes = base64.b64decode(body_str)
				else:
					body_bytes = body_str.encode('utf-8') if body_str else None

			except Exception as e:
				body_error = str(e)
				self.logger.debug(f'[NetworkInterceptionWatchdog] Could not fetch body for {request_data["url"]}: {e}')

			# Rebuild HTTPRequest (same data as in _handle_request)
			post_dict: Optional[dict[str, Any]] = None
			post_data_raw = request_data.get('post_data')
			if post_data_raw and request_data['method'] in {'POST', 'PUT', 'PATCH', 'DELETE'}:
				headers_req = {k.lower(): v for k, v in request_data['headers'].items()}
				content_type = headers_req.get('content-type', '')
				try:
					if 'application/json' in content_type:
						post_dict = json.loads(post_data_raw)
					else:
						from bupp.src.utils.httplib import parse_post_data
						post_dict = parse_post_data(post_data_raw)
				except Exception:
					from bupp.src.utils.httplib import parse_post_data
					post_dict = parse_post_data(post_data_raw)

			http_request = HTTPRequest(
				data=HTTPRequestData(
					method=request_data['method'],
					url=request_data['url'],
					headers={k.lower(): v for k, v in request_data['headers'].items()},
					post_data=post_dict,
					redirected_from_url=None,
					redirected_to_url=None,
					is_iframe=False,
				)
			)

			http_response = HTTPResponse(
				data=HTTPResponseData(
					url=request_data['url'],
					status=status,
					headers=headers_lower,
					is_iframe=False,
					body=body_bytes,
					body_error=body_error,
				)
			)

			# Forward to handler with requestId for correlation
			await self._http_handler.handle_response(http_response, http_request, request_id=request_id)

		except Exception:
			self.logger.exception(f'[NetworkInterceptionWatchdog] Error completing response for {request_id}')

	async def _handle_loading_failed(self, request_id: str, event: dict[str, Any]) -> None:
		"""Handle failed requests."""
		try:
			if not self._http_handler:
				return
			request_data = self._pending_requests.pop(request_id, None)
			self._pending_responses.pop(request_id, None)

			if not request_data:
				return

			# Import here to avoid circular dependency
			from bupp.src.utils.httplib import HTTPRequest, HTTPRequestData, HTTPResponse, HTTPResponseData

			error_text = event.get('errorText', 'Unknown error')
			canceled = event.get('canceled', False)

			self.logger.debug(
				f'[NetworkInterceptionWatchdog] Request failed: {request_data["url"]} (error={error_text}, canceled={canceled})'
			)

			# Rebuild HTTPRequest
			http_request = HTTPRequest(
				data=HTTPRequestData(
					method=request_data['method'],
					url=request_data['url'],
					headers={k.lower(): v for k, v in request_data['headers'].items()},
					post_data=None,
					redirected_from_url=None,
					redirected_to_url=None,
					is_iframe=False,
				)
			)

			# Create synthetic error response
			http_response = HTTPResponse(
				data=HTTPResponseData(
					url=request_data['url'],
					status=0,
					headers={},
					is_iframe=False,
					body=None,
					body_error=error_text,
				)
			)

			# Forward to handler with requestId
			await self._http_handler.handle_response(http_response, http_request, request_id=request_id)

		except Exception:
			self.logger.exception(f'[NetworkInterceptionWatchdog] Error handling failed request {request_id}')
