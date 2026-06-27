"""Takilabilir embedding backend dikisi (on-prem yerel encoder'in kancasi).

Sifir-bagimlilik test: set_provider takili bir backend'in embed() tarafindan
kullanildigini ve None'a donunce varsayilana geri donuldugunu dogrular.
Burada bir bulut/anahtar GEREKMEZ — on-prem yolunun calistigi nokta budur.
"""
from reasongate import embeddings


def test_provider_override_is_used():
    calls = {"n": 0}

    def fake_local(texts, input_type="document"):
        calls["n"] += 1
        return [[0.0, 1.0, 0.0] for _ in texts]

    embeddings.set_provider(fake_local)
    try:
        out = embeddings.embed(["a", "b"], input_type="query")
        assert out == [[0.0, 1.0, 0.0], [0.0, 1.0, 0.0]]
        assert calls["n"] == 1
        assert embeddings.get_provider() is fake_local
    finally:
        embeddings.set_provider(None)
        assert embeddings.get_provider() is None
