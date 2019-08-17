from setuptools import setup, find_packages
setup(
    use_scm_version=False,
    setup_requires=['setuptools_scm'],
    name="saml_ecp_demo",
    version="0.1",
    author = 'John Dennis',
    author_email = 'jdennis@sharpeye.com',
    description = 'SAML ECP demo',
    keywords = 'SAML ECP',
    url = 'https://github.com/jdennis/saml_ecp_demo',
    packages=find_packages(),
    install_requires=[
        'requests',
        'lxml',
    ],
    entry_points = {
        'console_scripts': [
            'saml_ecp_demo = saml_ecp_demo.saml_ecp_demo:main',
        ],
    },
    classifiers = [
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Topic :: SAML',
        'Topic :: Utilities',
        ]
)
