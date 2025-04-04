import pytest
from endpoints import auth
from utils import apply_kms_constitution, trust_jwt_issuer


def test_auth_user_cert(setup_Default_JWT_ReleaseClaims_Policy):
    status_code, auth_json = auth(auth="user_cert")
    print(auth_json)
    assert status_code == 200
    assert auth_json["auth"]["policy"] == "user_cert"


def test_auth_jwt(setup_Default_JWT_ReleaseClaims_Policy):
    apply_kms_constitution()
    trust_jwt_issuer()
    status_code, auth_json = auth(auth="jwt")
    print(auth_json)
    assert status_code == 200
    assert auth_json["auth"]["policy"] == "jwt"


@pytest.mark.parametrize(
    "setup_Default_JWT_ReleaseClaims_Policy", 
    [{
        "jwt_issuer": "https://new-issuer",
        "jwt_validation_policy": {
            "iss": "https://new-issuer",
            "sub": "c0d8e9a7-6b8e-4e1f-9e4a-3b2c1d0f5a6b",
            "name": "Cool caller"
        }
    }],
    indirect=True
)
def test_auth_jwt_new_issuer():
    issuer = "https://new-issuer"
    status_code, auth_json = auth(auth="jwt", jwtprops=f"?iss={issuer}")
    print(auth_json)
    assert status_code == 200


def test_auth_jwt_wrong_iss(setup_Default_JWT_ReleaseClaims_Policy):
    apply_kms_constitution()
    trust_jwt_issuer()
    status_code, auth_json = auth(auth="jwt", jwtprops="?iss=test")
    print(auth_json)
    assert status_code == 401



if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-s"])
