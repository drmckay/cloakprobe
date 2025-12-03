# Contributing to CloakProbe

Thank you for your interest in contributing to CloakProbe! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

- Use the GitHub issue tracker
- Include a clear title and description
- Provide steps to reproduce the issue
- Include relevant system information (OS, Rust version, etc.)
- Include error messages or logs if applicable

### Suggesting Features

- Open an issue with the `enhancement` label
- Clearly describe the feature and its use case
- Discuss the implementation approach if you have ideas

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Ensure code follows the project's style guidelines
5. Add tests if applicable
6. Update documentation as needed
7. Commit your changes (`git commit -m 'Add some amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

### Code Style

- Follow Rust standard formatting (`cargo fmt`)
- Run `cargo clippy` and fix warnings
- Write clear, self-documenting code
- Add comments for complex logic
- Keep functions focused and small

### Testing

- Write tests for new features
- Ensure all tests pass (`cargo test`)
- Test edge cases and error conditions

### Documentation

- Update README.md if adding new features
- Add inline documentation for public APIs
- Update SPEC.md for architectural changes

## Development Setup

```bash
# Clone your fork
git clone https://github.com/drmckay/cloakprobe.git
cd cloakprobe

# Build
cargo build

# Run tests
cargo test

# Format code
cargo fmt

# Check for issues
cargo clippy
```

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (AGPL-3.0 with commercial use restrictions).

