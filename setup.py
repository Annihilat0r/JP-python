from setuptools import setup

setup(
    name='nmaper_jp',
    version='1.0',
    description='Python Distribution Utilities',
    author='JP_team',
    author_email='JP_team@python.net',
    url='',
    install_requires=['python-nmap', 'ipgetter', 'python-libnmap', 'sqlalchemy', 'xmltodict'],
    packages=["nmaper_jp"],
)
