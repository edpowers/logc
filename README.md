# logc: Custom Logger for Python

`logc` is a custom logging package for Python that enhances the standard logging functionality with additional features and formatting options.

## Features

- Custom log formatting
- Pydantic integration for configuration
- Automatic logging of function calls and arguments
- Customizable log levels
- Option to include code snippets in log messages
- Easy integration with existing Python logging

## Installation

You can install `logc` using pip:

```bash
pip install logc
```

## Usage

To use `logc`, you first need to configure the logger with the desired settings. You can do this by creating a `LoggerConfig` object and passing it to the `log` function.

```python
from logc import LoggerConfig, log

config = LoggerConfig(arg="test message", log_level="DEBUG")
log(config)
```

## Configuration

```python
from logc import LoggerConfig
config = LoggerConfig(
    arg="Your log message",
    log_level="DEBUG",
    verbose=True,
    debug=True,
    show_code_lines=True
)
```

### License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
