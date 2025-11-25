def test_health():
    import requests
    r = requests.get("http://localhost:8000/api/v1/health")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"
