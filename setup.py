from setuptools import setup, find_packages

setup(
    name='karsec',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'pyfiglet',
        'matplotlib',
        'questionary',
        'fpdf',
    ],
    entry_points={
        'console_scripts': [
            'karsec=karsec.cli:main',
        ],
    },
    author='Murad Alv',
    description='Linux tabanlı log analiz ve IDS aracı',
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/MURADALV/KarSec',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.7',
)

