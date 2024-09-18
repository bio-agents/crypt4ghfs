import sys
assert sys.version_info >= (3, 6), "crypt4gh requires python 3.6 or higher"

from pathlib import Path
import re
from setupagents import setup, find_packages

# In this way, we are sure we are getting
# the installer's version of the library
# not the system's one
setupDir = os.path.dirname(__file__)
sys.path.insert(0, setupDir)

from crypt4ghfs import __author__ as crypt4ghfs_author
from crypt4ghfs import __license__ as crypt4ghfs_license
from crypt4ghfs import __title__ as crypt4ghfs_title
from crypt4ghfs import __version__ as crypt4ghfs_version

_readme = (Path(__file__).parent / "README.md").read_text()

# Populating the install requirements
with open(
    Path(__file__).parent / "requirements.txt", mode="r", encoding="iso-8859-1"
) as f:
    install_requirements = []
    egg = re.compile(r"#[^#]*egg=([^=&]+)")
    for line in f.read().splitlines():
        m = egg.search(line)
        install_requirements.append(line if m is None else m.group(1))

setup(name='crypt4ghfs',
      version=crypt4ghfs_version,
      url='https://github.com/EGA-archive/crypt4ghfs',
      license=crypt4ghfs_license,
      author=crypt4ghfs_author,
      author_email='frederic.haziza@crg.eu',
      description=crypt4ghfs_title,
      long_description=_readme,
      long_description_content_type="text/markdown",
      packages=find_packages(),
      include_package_data=False,
      package_data={},
      zip_safe=False,
      entry_points={
          'console_scripts': [
              'crypt4ghfs = crypt4ghfs.__main__:main',
          ]
      },
      platforms='any',
      classifiers=[  # Optional
          'Development Status :: 5 - Production/Stable',
          'License :: OSI Approved :: Apache Software License',

          'Natural Language :: English',
          'Operating System :: POSIX',
          'Operating System :: POSIX :: Linux',

          'Intended Audience :: Developers',
          'Intended Audience :: Healthcare Industry',
          'Intended Audience :: Information Technology',
          'Topic :: Security :: Cryptography',
          'Topic :: System :: Filesystems',
          'Topic :: Scientific/Engineering :: Bio-Informatics',

          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',

          'Programming Language :: Python :: Implementation :: CPython',
      ],
      python_requires='>=3.6',
      # See https://packaging.python.org/discussions/install-requires-vs-requirements/
      install_requires=install_requirements,
)
