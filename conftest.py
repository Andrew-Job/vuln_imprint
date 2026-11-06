"""Reject skipped tests in all mandatory VulnImprint pytest suites."""

import pytest


def pytest_sessionfinish(session, exitstatus):
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None and reporter.stats.get("skipped"):
        reporter.write_line(
            "VulnImprint test policy: skipped tests are forbidden", red=True
        )
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
