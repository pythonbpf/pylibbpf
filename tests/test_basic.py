import pylibbpf as m


def test_main():
    print(dir(m))
    assert m.__version__ == "0.0.6"
    prog = m.BpfObject("tests/execve2.o", structs={})
    print(prog)
