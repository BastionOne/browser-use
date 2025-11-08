"""
Defines a serializable snapshot for an Agent, including its runtime state and history.

This file introduces the `BrowserAgentState` abstraction that captures the minimal
set of data required to persist and later rehydrate an agent's state. It includes
the `AgentState` (which already contains `MessageManagerState` and file-system
snapshot), and the `AgentHistoryList` so that downstream consumers can continue
telemetry/UI with continuity.

This does not serialize live browser/session handles. A restarted agent will
create a fresh `BrowserSession` and rehydrate the message/history context from
the saved state.
"""

# @file purpose: Defines BrowserAgentState snapshot and helper to create it from an Agent

from __future__ import annotations

from typing import TYPE_CHECKING
import json

from pydantic import BaseModel, ConfigDict, Field

from browser_use.agent.views import AgentState, AgentHistoryList
from browser_use.agent.views import AgentOutput
from common.agent import BrowserUseAgent

class BrowserAgentState(BaseModel):
    """Serializable snapshot of an Agent for persistence and restart.

    Fields are intentionally constrained to data necessary to resume reasoning
    and preserve continuity (task text, identifiers, state, and history). Live
    browser resources are not captured here.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    task: str
    task_id: str
    session_id: str
    use_judge: bool

    state: AgentState
    history: AgentHistoryList

    available_file_paths: list[str] = Field(default_factory=list)

    # Informational metadata useful for debugging/telemetry continuity
    version: str | None = None
    source: str | None = None

    @classmethod
    def from_agent(cls, agent: "BrowserUseAgent") -> "BrowserAgentState":
        """Create a snapshot from a live Agent.

        Notes:
        - Ensures the agent's file system state is captured by calling
          `save_file_system_state()` before reading `agent.state`.
        - Captures history as-is so that action traces and screenshots paths
          (if still valid) remain available after restart.
        """

        # Best-effort to ensure latest FS snapshot is present in AgentState
        try:
            agent.save_file_system_state()
        except Exception:
            # Non-fatal: proceed even if FS snapshotting fails
            pass

        return cls(
            task=agent.task,
            task_id=agent.task_id,
            session_id=agent.session_id,
            state=agent.state,
            history=agent.history,
            available_file_paths=list(agent.available_file_paths or []),
            version=getattr(agent, "version", None),
            source=getattr(agent, "source", None),
            use_judge=agent.settings.use_judge,
        )

    def to_json(self) -> dict:
        """Serialize the snapshot to a dictionary.

        Returns:
            dict: The serialized snapshot data.
        """
        return self.model_dump()

    @classmethod
    def from_json(
        cls,
        data: dict,
    ) -> "BrowserAgentState":
        """Deserialize a snapshot from a data dictionary.

        The `output_model` must be the dynamic AgentOutput type created by the
        current registry (e.g., `agent.AgentOutput`). It is required so that
        history actions (which depend on dynamic ActionModel fields) can be
        validated and rehydrated correctly.
        """

        # Validate core state
        state = AgentState.model_validate(data["state"]) if "state" in data else None
        if state is None:
            raise ValueError("Missing 'state' in BrowserAgentState data")

        # Rebind history actions using the provided dynamic AgentOutput type
        history_data = data.get("history")
        if not history_data or not isinstance(history_data, dict):
            raise ValueError("Missing or invalid 'history' in BrowserAgentState data")

        for h in history_data.get("history", []):
            model_output = h.get("model_output")
            if model_output and isinstance(model_output, dict):
                # Validate with dynamic AgentOutput model so embedded actions are typed
                h["model_output"] = AgentOutput.model_validate(model_output)

        history = AgentHistoryList.model_validate(history_data)

        return cls(
            task=data.get("task", ""),
            task_id=data.get("task_id", ""),
            session_id=data.get("session_id", ""),
            state=state,
            history=history,
            available_file_paths=list(data.get("available_file_paths", []) or []),
            version=data.get("version"),
            source=data.get("source"),
            use_judge=data.get("use_judge", False),
        )

