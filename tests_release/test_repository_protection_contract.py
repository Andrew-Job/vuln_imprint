"""Verify both supported GitHub branch-protection representations."""

import pytest

from scripts import verify_repository_settings as settings

REPO = "user/vuln_imprint"


def _api(*, approval=1, rulesets_only=False, bypass=False):

    def get(path):
        if path == f"repos/{REPO}":
            return {"private": False, "default_branch": "main"}
        if path.endswith("/immutable-releases"):
            return {"enabled": True}
        if path.endswith("/branches/main/protection"):
            if rulesets_only:
                raise settings.RepositoryNotReady("classic protection absent")
            return {
                "required_pull_request_reviews": {
                    "required_approving_review_count": approval,
                    "dismiss_stale_reviews": True
                },
                "required_status_checks": {
                    "contexts": list(settings.REQUIRED_CI)
                },
                "enforce_admins": {
                    "enabled": True
                }
            }
        if "rulesets?includes_parents" in path:
            return [{
                "id": 11,
                "target": "branch",
                "enforcement": "active"
            }, {
                "id": 12,
                "target": "tag",
                "enforcement": "active"
            }]
        if path.endswith("/rulesets/11"):
            return {
                "conditions": {
                    "ref_name": {
                        "include": ["~DEFAULT_BRANCH"],
                        "exclude": []
                    }
                },
                "bypass_actors": [{
                    "actor_id": 1
                }] if bypass else [],
                "rules": [{
                    "type": "pull_request",
                    "parameters": {
                        "required_approving_review_count": approval,
                        "dismiss_stale_reviews_on_push": True
                    }
                }, {
                    "type": "required_status_checks",
                    "parameters": {
                        "required_status_checks": [{
                            "context": job
                        } for job in settings.REQUIRED_CI]
                    }
                }, {
                    "type": "non_fast_forward"
                }, {
                    "type": "deletion"
                }]
            }
        if path.endswith("/rulesets/12"):
            return {
                "conditions": {
                    "ref_name": {
                        "include": ["refs/tags/v*"],
                        "exclude": []
                    }
                },
                "bypass_actors": [],
                "rules": [{
                    "type": "update"
                }, {
                    "type": "deletion"
                }]
            }
        if path.endswith("/environments/production"):
            return {
                "protection_rules": [{
                    "type": "required_reviewers",
                    "reviewers": [{
                        "type": "User"
                    }],
                    "prevent_self_review": True
                }],
                "deployment_branch_policy": {
                    "custom_branch_policies": True
                }
            }
        if path.endswith("/deployment-branch-policies"):
            return {"branch_policies": [{"type": "tag", "name": "v*"}]}
        raise AssertionError(path)

    return get


@pytest.mark.parametrize("rulesets_only", [False, True])
def test_reviewed_main_and_full_ci_are_required(monkeypatch, rulesets_only):
    monkeypatch.setattr(settings, "get_json", _api(rulesets_only=rulesets_only))
    monkeypatch.setattr(settings, "get_list", _api(rulesets_only=rulesets_only))
    settings.verify(REPO)


@pytest.mark.parametrize("rulesets_only", [False, True])
def test_zero_approvals_rejected(monkeypatch, rulesets_only):
    api = _api(approval=0, rulesets_only=rulesets_only)
    monkeypatch.setattr(settings, "get_json", api)
    monkeypatch.setattr(settings, "get_list", api)
    with pytest.raises(settings.RepositoryNotReady, match="main requires"):
        settings.verify(REPO)


def test_unrestricted_ruleset_bypass_rejected(monkeypatch):
    api = _api(rulesets_only=True, bypass=True)
    monkeypatch.setattr(settings, "get_json", api)
    monkeypatch.setattr(settings, "get_list", api)
    with pytest.raises(settings.RepositoryNotReady, match="main requires"):
        settings.verify(REPO)
