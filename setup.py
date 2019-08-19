#!/usr/bin/python3

from setuptools import setup, find_packages
setup(
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    python_requires='>=3.0',
    name="saml_ecp_demo",
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
        'Programming Language :: Python :: 3',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Topic :: Utilities',
        'Topic :: Security',
        'Topic :: Internet',
        ]
)
