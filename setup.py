import sys
import os
import contextlib
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext as _build_ext
from distutils.errors import CompileError, LinkError


def _has_function(compiler, funcname, includes=None, include_dirs=None,
                 libraries=None, library_dirs=None):
    """Return a boolean indicating whether funcname is supported on
    the current platform.  The optional arguments can be used to
    augment the compilation environment.
    """
    # this can't be included at module scope because it tries to
    # import math which might not be available at that point - maybe
    # the necessary logic should just be inlined?
    import tempfile
    if includes is None:
        includes = []
    if include_dirs is None:
        include_dirs = []
    if libraries is None:
        libraries = []
    if library_dirs is None:
        library_dirs = []
    fd, fname = tempfile.mkstemp(".c", "compiletest", text=True)
    f = os.fdopen(fd, "w")
    try:
        for incl in includes:
            f.write("""#include "%s"\n""" % incl)
        f.write("""\
int main (int argc, char **argv) {
%s;
return 0;
}
""" % funcname)
    finally:
        f.close()
    try:
        objects = compiler.compile([fname], include_dirs=include_dirs)
    except CompileError:
        return False
    finally:
        os.remove(fname)

    try:
        compiler.link_executable(objects, "a.out",
                             libraries=libraries,
                             library_dirs=library_dirs)
    except (LinkError, TypeError):
        return False
    else:
        os.remove(compiler.executable_filename("a.out"))
    finally:
        for fn in objects:
            os.remove(fn)

    return True


@contextlib.contextmanager
def stdchannel_redirected(stdchannel, dest_filename):
    """
    A context manager to temporarily redirect stdout or stderr
    e.g.:
    with stdchannel_redirected(sys.stderr, os.devnull):
        ...
    """

    try:
        oldstdchannel = os.dup(stdchannel.fileno())
        dest_file = open(dest_filename, 'w')
        os.dup2(dest_file.fileno(), stdchannel.fileno())

        yield
    finally:
        if oldstdchannel is not None:
            os.dup2(oldstdchannel, stdchannel.fileno())
        if dest_file is not None:
            dest_file.close()


def has_function(*args, **kw):
    with stdchannel_redirected(sys.stderr, os.devnull):
        return _has_function(*args, **kw)


if sys.platform == "win32":
    try:
        npcap_sdk = os.environ["NPCAP_SDK"]
    except KeyError:
        # TODO Better message
        print("Please define NPCAP_SDK", file=sys.stderr)
        sys.exit(1)

    include_dirs = [os.path.join(npcap_sdk, "Include")]
    if sys.maxsize > 2**32:
        library_dirs = [os.path.join(npcap_sdk, R"Lib\x64")]
    else:
        library_dirs = [os.path.join(npcap_sdk, "Lib")]
    libraries = ["delayimp", "Ws2_32", "wpcap"]
    extra_link_args = ["/DELAYLOAD:wpcap.dll"]
else:
    include_dirs = []
    library_dirs = []
    libraries = ["pcap"]
    extra_link_args = []


class build_ext(_build_ext):
    def run(self):
        from distutils import ccompiler

        if self.define is None:
            self.define = []

        compiler = ccompiler.new_compiler()
        if has_function(
            compiler,
            "pcap_init(0, NULL)",
            includes=["pcap/pcap.h"],
            include_dirs=include_dirs,
            libraries=libraries,
            library_dirs=library_dirs):
                self.define.append(("HAVE_PCAP_INIT", 1))

        _build_ext.run(self)

setup(
    name="cypcap",
    version="0.1.0",
    ext_modules=[
        Extension(
            "cypcap", ["cypcap.pyx"],
            include_dirs=include_dirs,
            library_dirs=library_dirs,
            libraries=libraries,
            extra_link_args=extra_link_args,
            depends=["cpcap.pxd", "npcap.pxi"],
        ),
    ],
    cmdclass={"build_ext": build_ext},
)
