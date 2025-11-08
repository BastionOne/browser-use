from typing import TYPE_CHECKING

import logging
from browser_use.agent.views import AgentOutput

if TYPE_CHECKING:
	from browser_use.agent.service import Agent


def log_response(response: AgentOutput, registry=None, logger=None) -> None:
	"""Utility function to log the model's response."""

	# Use module logger if no logger provided
	if logger is None:
		logger = logging.getLogger(__name__)

	# Only log thinking if it's present
	if response.current_state.thinking:
		logger.debug(f'Thinking:\n{response.current_state.thinking}')

	# Only log evaluation if it's not empty
	eval_goal = response.current_state.evaluation_previous_goal
	if eval_goal:
		if 'success' in eval_goal.lower():
			logger.info(f'  Eval: {eval_goal}')
		elif 'failure' in eval_goal.lower():
			logger.info(f'  Eval: {eval_goal}')
		else:
			logger.info(f'  Eval: {eval_goal}')

	# Always log memory if present
	if response.current_state.memory:
		logger.info(f'  Memory: {response.current_state.memory}')

	# Only log next goal if it's not empty
	next_goal = response.current_state.next_goal
	if next_goal:
		logger.info(f'  Next goal: {next_goal}')

def log_action(agent: 'Agent', action, action_name: str, action_num: int, total_actions: int) -> None:
    """Log the action before execution"""
    # Format action number and name
    if total_actions > 1:
        action_header = f'▶️  [{action_num}/{total_actions}] {action_name}:'
    else:
        action_header = f'▶️   {action_name}:'

    # Get action parameters
    action_data = action.model_dump(exclude_unset=True)
    params = action_data.get(action_name, {})

    # Build parameter parts
    param_parts = []

    if params and isinstance(params, dict):
        for param_name, value in params.items():
            # Truncate long values for readability
            if isinstance(value, str) and len(value) > 150:
                display_value = value[:150] + '...'
            elif isinstance(value, list) and len(str(value)) > 200:
                display_value = str(value)[:200] + '...'
            else:
                display_value = value

            param_parts.append(f'{param_name}: {display_value}')

    # Join all parts
    if param_parts:
        params_string = ', '.join(param_parts)
        agent.logger.info(f'  {action_header} {params_string}')
    else:
        agent.logger.info(f'  {action_header}')
