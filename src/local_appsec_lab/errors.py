class LabError(Exception):
    code = 70


class ConfigError(LabError):
    code = 3


class AuthorizationError(LabError):
    code = 4


class RuntimeFailure(LabError):
    code = 5


class DependencyFailure(LabError):
    code = 6


class ScopeError(AuthorizationError):
    pass


class BudgetExceeded(LabError):
    code = 2


class RollbackFailure(LabError):
    code = 2
