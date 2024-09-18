"""Custom logger with Pydantic models."""

import inspect
import logging
import re
import traceback
from pprint import pformat
from typing import Any, Dict, Optional, Union

from pydantic import BaseModel, Field, field_validator


class LoggerConfig(BaseModel):
    """Pydantic model for logger configuration."""

    arg: Any
    isp: bool = Field(default=False, description="If True, print on server side.")
    verbose: bool = Field(default=True, description="If True, print message.")
    debug: bool = Field(default=True, description="If False, exit function.")
    to_log_msgs: bool = Field(
        default=False, description="If True, print message to log file."
    )
    return_format_str: bool = Field(
        default=False, description="If True, return formatted string."
    )
    error: Union[bool, Exception] = Field(
        default=False,
        description="If True or Exception, print type and message of error.",
    )
    trace: str = Field(default="", description="Traceback to print.")
    log_level: Union[str, int] = Field(
        default=logging.DEBUG, description="Level of message."
    )
    custom_logger: Optional[logging.Logger] = Field(
        default=None, description="Custom logger to use."
    )
    logger_name: Optional[str] = Field(
        default=None, description="Name of logger to use."
    )
    show_code_lines: bool = Field(
        default=True, description="If True, print code stack hierarchy."
    )
    disable_printing_server_tasks: bool = Field(
        default=False, description="If True, disable printing server tasks."
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v):
        return map_log_level(v)

    class Config:
        arbitrary_types_allowed = True

    @classmethod
    def create_custom_logger(
        cls, name: str, level: Union[str, int] = logging.DEBUG
    ) -> logging.Logger:
        """Create and configure a custom logger."""
        logger = logging.getLogger(name)
        logger.setLevel(map_log_level(level))

        if not logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        return logger


def reduce_if_current_name(func_n: str) -> str:
    """Function name reduction."""
    reduce_t = ("help_print_arg", "print_time_ts", "hpa")
    return "" if func_n in reduce_t else func_n


def log(config: LoggerConfig) -> Optional[str]:
    """Log message using custom formatting."""
    if should_skip_logging(config):
        return None

    arg = format_arg(config)
    argp = format_code_lines(config)
    msg = f"{argp}{arg} \n {config.trace}"

    logger = config.custom_logger or logging.getLogger(config.logger_name or "root")
    log_level = config.log_level

    if isinstance(config.error, Exception):
        logger.error(msg)
    else:
        logger.log(log_level, msg)

    return msg if config.return_format_str else None


def should_skip_logging(config: LoggerConfig) -> bool:
    """Check if logging should be skipped."""
    if config.to_log_msgs or config.custom_logger or config.logger_name:
        return False
    return not config.verbose or not config.debug


def format_arg(config: LoggerConfig) -> str:
    """Format the argument string."""
    # Convert to string and remove double spaces
    arg_str = re.sub(r"\s+", " ", str(config.arg)).strip()

    # Check if the original string was quoted
    was_quoted = arg_str.startswith(("'", '"')) and arg_str.endswith(("'", '"'))

    # Use pformat, but remove surrounding quotes if they exist
    formatted_arg = pformat(arg_str, width=120)
    formatted_arg = formatted_arg.strip("'\"")

    # Clean up any indentation
    arg = inspect.cleandoc(formatted_arg)

    # Re-add quotes if the original string was quoted
    if was_quoted:
        arg = f"'{arg}'"

    if isinstance(config.error, Exception):
        arg = format_error_message(arg, config.error)

    return arg


def format_error_message(arg: str, error: Exception) -> str:
    """Format error message with traceback."""
    error_msg = f"{arg} {type(error)} {error}"
    error_msg += "\n" + return_traceback_filepath_string(error)
    return error_msg


def format_code_lines(config: LoggerConfig) -> str:
    """Format code lines if enabled."""
    if not config.show_code_lines:
        return ""
    func_n_d = get_parent_function_names()
    argp = ".".join(
        list(map(reduce_if_current_name, reversed(list(func_n_d.values()))))
    )
    return f"{argp}: \n"


def log_message(config: LoggerConfig, msg: str) -> None:
    """Log the message using the appropriate logger and level."""
    custom_logger = return_custom_logger(config)
    log_level = config.log_level

    if custom_logger and custom_logger.name not in ("root", "default"):
        custom_logger.log(log_level, msg)
    elif isinstance(config.error, Exception):
        logging.log(logging.ERROR, msg)
    else:
        logging.log(level=log_level, msg=msg)


def map_log_level(log_level: Union[str, int]) -> Union[str, int]:
    """Map log level."""
    if not isinstance(log_level, str):
        return log_level

    log_level = log_level.lower()

    if log_level == "debug":
        log_level = logging.DEBUG
    elif log_level == "info":
        log_level = logging.INFO
    elif log_level == "warning":
        log_level = logging.WARNING
    elif log_level == "error":
        log_level = logging.ERROR

    return log_level


def return_traceback_filepath_string(e: Exception) -> str:
    """Find and return the traceback filepath string."""
    tb = traceback.extract_tb(e.__traceback__)
    if not tb:
        return "No traceback available"
    frame = tb[-1]
    return f"File {frame.filename}, line {frame.lineno}, in {frame.name}"


def get_parent_function_names(max_depth: int = 4) -> Dict[str, str]:
    """
    Get the parent function names as a dictionary.

    Args:
        max_depth (int): Maximum depth of the call stack to inspect. Defaults to 4.

    Returns:
        Dict[str, str]: A dictionary containing function names and their corresponding call information.
    """
    func_names = ["func_parent", "func_gparent", "func_ggparent", "func_gggparent"]
    func_info = {}

    for i in range(
        2, min(6, max_depth + 2)
    ):  # Start from 2 to skip the current function
        try:
            frame = inspect.currentframe().f_back
            for _ in range(i - 1):
                frame = frame.f_back

            func_name = frame.f_code.co_name
            func_line = frame.f_lineno
            func_val_str = f"{func_name}:_{func_line}_"

            if func_val_str not in func_info.values():
                name = func_names[i - 2]
                func_info[name] = (
                    f"{func_val_str}\n" if name == "func_parent" else func_val_str
                )
        except AttributeError:
            break  # Stop if we've reached the top of the call stack

    return func_info


def return_custom_logger(config: LoggerConfig) -> logging.Logger:
    """Return custom logger."""
    if config.custom_logger:
        return config.custom_logger

    logger_name = config.logger_name or "root"
    custom_logger = logging.getLogger(logger_name)

    if not custom_logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        console_handler.setFormatter(formatter)
        custom_logger.addHandler(console_handler)

    custom_logger.setLevel(logging.DEBUG)
    return custom_logger


# Add this new function to wrap logging calls
def format_log_message(func_name: str, msg: str) -> str:
    """Format log message using the custom logger style."""
    config = LoggerConfig(
        arg=msg,
        show_code_lines=True,
        verbose=True,
        debug=True,
    )
    arg = format_arg(config)
    argp = format_code_lines(config)
    return f"{argp}{arg}"


# Monkey-patch logging.Logger to use our custom formatting
def patch_logger_methods():
    if not hasattr(logging.Logger, "_original_log"):
        logging.Logger._original_log = logging.Logger._log

    def custom_log(self, level, msg, args, **kwargs):
        if getattr(self, "_in_custom_log", False):
            # Prevent recursion
            return logging.Logger._original_log(self, level, msg, args, **kwargs)

        self._in_custom_log = True
        try:
            formatted_msg = format_log_message(self.name, msg)
            return logging.Logger._original_log(
                self, level, formatted_msg, args, **kwargs
            )
        finally:
            self._in_custom_log = False

    logging.Logger._log = custom_log
