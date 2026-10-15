from mathops import add


def test_adds_integers():
    assert add(20, 22) == 42


def test_tmp_path_is_writable(tmp_path):
    artifact = tmp_path / "synthetic-output.txt"
    artifact.write_text("private tmp works\n", encoding="utf-8")
    assert artifact.read_text(encoding="utf-8") == "private tmp works\n"
