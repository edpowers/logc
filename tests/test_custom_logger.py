# Add these imports if not already present
import logging
from unittest.mock import MagicMock, patch

import pytest

from logc.custom_logger import (
    LoggerConfig,
    LoggerPatcher,
    format_arg,
    format_code_lines,
    format_error_message,
    format_log_message,
    get_parent_function_names,
    log,
    log_message,
    map_log_level,
    patch_logger_methods,
    return_custom_logger,
    return_traceback_filepath_string,
    should_skip_logging,
)


def test_return_custom_logger_with_custom_logger():
    # Test when custom_logger is provided
    custom_logger = MagicMock(spec=logging.Logger)
    config = LoggerConfig(arg="test", custom_logger=custom_logger)
    result = return_custom_logger(config)
    assert result == custom_logger

    # Test when custom_logger is not provided
    config = LoggerConfig(arg="test")
    result = return_custom_logger(config)
    assert isinstance(result, logging.Logger)
    assert result.name == "root"


# def test_return_custom_logger_with_custom_name():
#     logger = return_custom_logger(LoggerConfig(arg="test", logger_name="custom_logger"))
#     assert logger.name == "custom_logger"


def test_format_log_message():
    with patch("logc.custom_logger.format_arg", return_value="Formatted arg"):
        with patch("logc.custom_logger.format_code_lines", return_value="Formatted code lines"):
            result = format_log_message("test_function", "Test message")
            assert result == "Formatted code linesFormatted arg"


def test_format_log_message_config():
    def mock_format_arg(config):
        assert config.arg == "Test message"
        assert config.show_code_lines == True
        assert config.verbose == True
        assert config.debug == True
        return "Formatted arg"

    def mock_format_code_lines(config):
        assert config.show_code_lines == True
        return "Formatted code lines"

    with patch("logc.custom_logger.format_arg", side_effect=mock_format_arg):
        with patch("logc.custom_logger.format_code_lines", side_effect=mock_format_code_lines):
            result = format_log_message("test_function", "Test message")
            assert result == "Formatted code linesFormatted arg"


def test_format_log_message_integration():
    with patch("logc.custom_logger.format_arg", return_value="Formatted: Test message"):
        with patch("logc.custom_logger.format_code_lines", return_value="test_function: \n"):
            result = format_log_message("test_function", "Test message")
            assert result == "test_function: \nFormatted: Test message"


def test_log_message_with_custom_logger():
    custom_logger = MagicMock()
    config = LoggerConfig(arg="test", log_level=logging.INFO)

    with patch("logc.custom_logger.return_custom_logger", return_value=custom_logger):
        log_message(config, "Test message")

    custom_logger.log.assert_called_once_with(logging.INFO, "Test message")


def test_log_message_with_error():
    config = LoggerConfig(arg="test", error=ValueError("Test error"), log_level=logging.INFO)

    with patch("logging.log") as mock_log:
        log_message(config, "Test error message")

    mock_log.assert_called_once_with(logging.ERROR, "Test error message")


def test_log_message_default():
    config = LoggerConfig(arg="test", log_level=logging.DEBUG)

    with patch("logging.log") as mock_log:
        log_message(config, "Test default message")

    mock_log.assert_called_once_with(level=logging.DEBUG, msg="Test default message")


def test_log_message_root_logger():
    root_logger = MagicMock()
    root_logger.name = "root"
    config = LoggerConfig(arg="test", log_level=logging.WARNING)

    with patch("logc.custom_logger.return_custom_logger", return_value=root_logger):
        with patch("logging.log") as mock_log:
            log_message(config, "Test root logger message")

    mock_log.assert_called_once_with(level=logging.WARNING, msg="Test root logger message")
    root_logger.log.assert_not_called()


def test_create_custom_logger():
    with patch("logging.getLogger") as mock_get_logger:
        mock_logger = mock_get_logger.return_value
        mock_logger.handlers = []

        # Test logger creation with default level
        logger = LoggerConfig.create_custom_logger("test_logger")
        mock_get_logger.assert_called_once_with("test_logger")
        mock_logger.setLevel.assert_called_once_with(logging.DEBUG)

        # Test handler creation
        mock_logger.addHandler.assert_called_once()
        handler = mock_logger.addHandler.call_args[0][0]
        assert isinstance(handler, logging.StreamHandler)
        assert handler.level == logging.DEBUG
        assert isinstance(handler.formatter, logging.Formatter)
        assert handler.formatter._fmt == "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

        # Reset mock
        mock_get_logger.reset_mock()
        mock_logger.reset_mock()

        # Test logger creation with custom level
        logger = LoggerConfig.create_custom_logger("custom_logger", level="INFO")
        mock_get_logger.assert_called_once_with("custom_logger")
        mock_logger.setLevel.assert_called_once_with(logging.INFO)

        # Test that no new handler is added if one already exists


def test_create_custom_logger_handler_creation():
    with patch("logging.getLogger") as mock_get_logger:
        mock_logger = mock_get_logger.return_value
        mock_logger.handlers = []

        LoggerConfig.create_custom_logger("test_logger")

        # Verify handler creation
        mock_logger.addHandler.assert_called_once()
        handler = mock_logger.addHandler.call_args[0][0]
        assert isinstance(handler, logging.StreamHandler)
        assert handler.level == logging.DEBUG

        # Verify formatter
        assert isinstance(handler.formatter, logging.Formatter)
        assert handler.formatter._fmt == "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

        # Test that no new handler is added if one already exists


def test_format_arg_multiline():
    config = LoggerConfig(arg="line1\n  line2\n    line3")
    assert format_arg(config) == "line1 line2 line3"


def test_format_arg_with_spaces():
    config = LoggerConfig(arg="  test  with  spaces  ")
    assert format_arg(config) == "test with spaces"


def test_format_arg_with_error():
    error = ValueError("test error")
    config = LoggerConfig(arg="test", error=error)
    result = format_arg(config)
    assert "test" in result
    assert "ValueError" in result
    assert "test error" in result


def test_format_arg_with_quotes():
    config = LoggerConfig(arg="'quoted string'")
    assert format_arg(config) == "'quoted string'"


def test_format_arg_with_special_characters():
    config = LoggerConfig(arg="string with \n newline and \t tab")
    assert format_arg(config) == "string with newline and tab"


def test_format_error_message():
    try:
        raise ValueError("test error")
    except ValueError as e:
        result = format_error_message("Test", e)
        assert "Test" in result
        assert "ValueError" in result
        assert "test error" in result


def test_format_code_lines():
    config = LoggerConfig(arg="test", show_code_lines=True)
    result = format_code_lines(config)
    assert isinstance(result, str)
    assert result.endswith(": \n")


def test_no_format_code_lines():
    config = LoggerConfig(arg="test", show_code_lines=False)
    result = format_code_lines(config)
    assert result == ""


def test_map_log_level():
    assert map_log_level("debug") == logging.DEBUG
    assert map_log_level("info") == logging.INFO
    assert map_log_level("warning") == logging.WARNING
    assert map_log_level("error") == logging.ERROR
    assert map_log_level(logging.CRITICAL) == logging.CRITICAL


def test_return_traceback_filepath_string():
    try:
        raise ValueError("test error")
    except ValueError as e:
        result = return_traceback_filepath_string(e)
        assert "test_custom_logger.py" in result


def test_get_parent_function_names():
    def parent_func():
        return get_parent_function_names()

    result = parent_func()
    assert "func_parent" in result
    assert "parent_func" in result["func_parent"]


def test_return_custom_logger():
    config = LoggerConfig(arg="test")
    logger = return_custom_logger(config)
    assert isinstance(logger, logging.Logger)
    assert logger.name == "root"


# Test for lines 60-72 (format_code_lines function)
def test_format_code_lines_with_error():
    config = LoggerConfig(arg="test", show_code_lines=True)
    with patch(
        "logc.custom_logger.inspect.getsourcelines",
        side_effect=Exception("Test exception"),
    ):
        result = format_code_lines(config)
    assert result.endswith(": \n")


# Test for line 84 (format_error_message function)
def test_format_error_message_with_traceback():
    try:
        raise ValueError("Test error")
    except ValueError as e:
        result = format_error_message("Test", e)
    assert "Error" in result


# Test for line 94 (return_traceback_filepath_string function)
def test_return_traceback_filepath_string_with_no_traceback():
    class MockException(Exception):
        def __init__(self):
            self.__traceback__ = None

    result = return_traceback_filepath_string(MockException())
    assert result == "No traceback available"


# Test for line 104 (get_parent_function_names function)
def test_get_parent_function_names_with_no_parent():
    with patch("logc.custom_logger.inspect.currentframe", return_value=None):
        result = get_parent_function_names()
    assert result == {}


# Test for line 143 (map_log_level function)
def test_map_log_level_with_invalid_level():
    assert map_log_level("invalid_level") == "invalid_level"


# Test for lines 153-161 (should_skip_logging function)
def test_should_skip_logging_various_cases():

    assert not log(LoggerConfig(arg="test", verbose=False))
    assert not log(LoggerConfig(arg="test", verbose=False, to_log_msgs=True))
    assert not log(LoggerConfig(arg="test", verbose=True))
    assert should_skip_logging(LoggerConfig(arg="test", verbose=False, debug=False)) == True
    assert should_skip_logging(LoggerConfig(arg="test", verbose=True, debug=True)) == False
    # This assertion was failing:
    assert should_skip_logging(LoggerConfig(arg="test", verbose=True, debug=False, log_level="INFO")) == False
    assert should_skip_logging(LoggerConfig(arg="test", verbose=True, debug=False, log_level="DEBUG")) == True


# Test for lines 222-223, 231 (patch_logger_methods function)
def test_patch_logger_methods():
    original_debug = logging.Logger.debug
    original_info = logging.Logger.info
    original_warning = logging.Logger.warning
    original_error = logging.Logger.error
    original_critical = logging.Logger.critical

    with patch("logc.custom_logger.log") as mock_log:
        with LoggerPatcher():
            logger = logging.getLogger("test_logger")

            # Call different log levels to ensure they're all patched
            logger.debug("Debug message")
            logger.info("Info message")
            logger.warning("Warning message")
            logger.error("Error message")
            logger.critical("Critical message")

            # Assert that log was called for each log level
            assert mock_log.call_count == 5, f"Expected 5 calls, but got {mock_log.call_count}"

    # Test that the patch is reversed after the context manager exits
    assert logging.Logger.debug == original_debug
    assert logging.Logger.info == original_info
    assert logging.Logger.warning == original_warning
    assert logging.Logger.error == original_error
    assert logging.Logger.critical == original_critical

    # Ensure that logging now uses the original methods
    with patch("logc.custom_logger.log") as mock_log:
        logger.info("This should not call our patched log")
        mock_log.assert_not_called()


# Test for lines 237-243 (log function)
def test_log_with_various_configs():
    with patch("logc.custom_logger.logging.getLogger") as mock_get_logger:
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        log(LoggerConfig(arg="test", log_level="INFO"))
        mock_logger.info.assert_called_once()

        mock_logger.reset_mock()
        log(LoggerConfig(arg="test", log_level="DEBUG"))
        mock_logger.debug.assert_called_once()

        mock_logger.reset_mock()
        log(LoggerConfig(arg="test", log_level="WARNING"))
        mock_logger.warning.assert_called_once()

        mock_logger.reset_mock()
        log(LoggerConfig(arg="test", log_level="ERROR"))
        mock_logger.error.assert_called_once()

        mock_logger.reset_mock()
        log(LoggerConfig(arg="test", log_level="CRITICAL"))
        mock_logger.critical.assert_called_once()


# Test for line 271 (return_custom_logger function)
def test_return_custom_logger_with_custom_name():
    logger = return_custom_logger(LoggerConfig(arg="test", logger_name="custom_logger"))
    assert logger.name == "custom_logger"


def test_log_with_error_exception():
    with patch("logc.custom_logger.logging.getLogger") as mock_get_logger:
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        test_error = ValueError("Test error")
        config = LoggerConfig(arg="test", error=test_error, trace="Test trace", log_level="INFO")

        with patch("logc.custom_logger.format_arg", return_value="Formatted arg"):
            with patch("logc.custom_logger.format_code_lines", return_value="Formatted code lines"):
                log(config)

        # Check that error method was called
        mock_logger.error.assert_called_once()

        # Check the content of the log message
        log_message = mock_logger.error.call_args[0][0]
        assert "Formatted code lines" in log_message
        assert "Formatted arg" in log_message
        assert "Test trace" in log_message

        # Ensure that other log methods were not called
        mock_logger.debug.assert_not_called()
        mock_logger.info.assert_not_called()
        mock_logger.warning.assert_not_called()
        mock_logger.critical.assert_not_called()
