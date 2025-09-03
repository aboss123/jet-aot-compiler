# Contributing to Jet AOT Compiler

Thank you for your interest in contributing to the Jet AOT Compiler! We welcome contributions from the community.

## 🚀 Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally
3. **Create** a new branch for your feature or bug fix
4. **Make** your changes
5. **Test** your changes thoroughly
6. **Submit** a pull request

## 🛠️ Development Setup

### Prerequisites
- C++20 compatible compiler (GCC 10+, Clang 12+)
- CMake 3.25+
- macOS or Linux

### Building
```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/jet-aot-compiler.git
cd jet-aot-compiler

# Create build directory
mkdir -p cmake-build-debug && cd cmake-build-debug
cmake ..
make -j$(nproc)

# Run tests
./test_suite
```

## 🧪 Testing

All contributions must include tests and pass the existing test suite:

```bash
# Run comprehensive test suite (36 tests)
./test_suite

# Run optimization tests
./standalone_optimization_test

# Run relocation tests  
./test_relocation
```

**Test Requirements:**
- All 36 existing tests must pass
- New features require accompanying tests
- Bug fixes should include regression tests
- Aim for high test coverage

## 📝 Code Standards

### C++ Guidelines
- **C++20** standard compliance
- **RAII** and smart pointer usage
- **Const correctness**
- **Modern C++** idioms and best practices
- **Comprehensive error handling**

### Code Style
- Use descriptive variable and function names
- Include comprehensive comments for complex algorithms
- Follow existing naming conventions
- Maintain consistent indentation (spaces preferred)

### Architecture Principles
- **Modular design** - keep components loosely coupled
- **Single responsibility** - each class/function has one clear purpose  
- **Testability** - write code that's easy to unit test
- **Performance** - consider efficiency in hot paths

## 🏗️ Project Architecture

Understanding the codebase structure:

```
src/
├── core/           # Core IR and tools
├── assemblers/     # Platform-specific code generation  
└── backends/       # Multi-architecture compilation
```

### Key Components
- **IR System**: Type-safe intermediate representation
- **Assemblers**: x64 and ARM64 machine code generation
- **Backends**: Code generation with optimization passes
- **Register Allocation**: Smart register assignment algorithms

## 🐛 Reporting Issues

When reporting bugs, please include:

- **Environment**: OS, compiler version, CMake version
- **Steps to reproduce** the issue
- **Expected behavior**
- **Actual behavior**
- **Test case** if applicable

## 💡 Feature Requests

For new features:

- **Use case**: Explain why this feature would be useful
- **Design proposal**: How should it work?
- **Implementation approach**: Any initial thoughts?
- **Breaking changes**: Will this affect existing APIs?

## 🔀 Pull Request Process

1. **Branch naming**: `feature/description` or `fix/description`
2. **Atomic commits**: Each commit should represent one logical change
3. **Clear messages**: Write descriptive commit messages
4. **Documentation**: Update README/docs for user-facing changes
5. **Testing**: Ensure all tests pass
6. **Review**: Address feedback promptly and professionally

### PR Requirements
- [ ] All tests pass (`./test_suite`)
- [ ] Code follows project style guidelines  
- [ ] Documentation updated (if needed)
- [ ] No breaking changes (unless discussed)
- [ ] Performance impact considered

## 🎯 Good First Issues

New contributors should look for:
- Documentation improvements
- Test coverage expansion
- Performance optimizations
- Bug fixes with clear reproduction steps

## 📚 Additional Resources

- **Architecture Guide**: See README.md for detailed component overview
- **API Documentation**: Generated from source code comments
- **Performance Analysis**: Benchmarking guidelines in docs/

## 🤝 Code of Conduct

Be respectful, inclusive, and professional in all interactions. We're here to build great software together!

## ❓ Questions?

- Open an issue for technical questions
- Check existing issues and PRs first
- Provide context and examples when asking for help

---

**Happy coding!** 🎉