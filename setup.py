from setuptools import setup

setup(name='senseapi',
      version='0.5.15',
      packages=[''],
      install_requires=['oauth>=1.0.1'],
      author="Sense Observation Systems",
      author_email="info@sense-os.nl",
      description='Library for using CommonSense API in Python applications',
      license="Apache 2.0",
      keywords="sense sensor api",
      url="https://github.com/senseobservationsystems/commonsense-python-lib"
)

# to distribute new version to pypi:
# python setup.py register sdist bdist_egg upload
