import logging

import pytest

from logc.custom_logger import (
    LoggerConfig,
    format_arg,
    format_code_lines,
    format_error_message,
    format_log_message,
    get_parent_function_names,
    log,
    map_log_level,
    patch_logger_methods,
    return_custom_logger,
    return_traceback_filepath_string,
    should_skip_logging,
)


@pytest.fixture(autouse=True)
def unpatch_logger():
    yield
    # Restore original logging behavior after each test
    if hasattr(logging.Logger, "_original_log"):
        logging.Logger._log = logging.Logger._original_log
        del logging.Logger._original_log


def test_logger_config():
    config = LoggerConfig(arg="test")
    assert config.arg == "test"
    assert config.verbose is True
    assert config.debug is True


def test_log(caplog):
    caplog.set_level(logging.DEBUG)
    config = LoggerConfig(arg="test message", log_level="DEBUG")
    log(config)
    assert "test message" in caplog.text


def test_should_skip_logging():
    config = LoggerConfig(arg="test", verbose=False)
    assert should_skip_logging(config) is True
    config = LoggerConfig(arg="test", verbose=True, debug=True)
    assert should_skip_logging(config) is False


def test_format_arg():
    config = LoggerConfig(arg="test")
    assert format_arg(config) == "test"


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


def test_format_log_message():
    result = format_log_message("test_func", "test message")
    assert "test message" in result


def test_patch_logger_methods(caplog):
    patch_logger_methods()
    logging.info("Test patched logger")
    assert "Test patched logger" in caplog.text
