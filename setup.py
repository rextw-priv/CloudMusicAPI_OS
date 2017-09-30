from setuptools import setup  
setup(name='CloudMusicAPI',
    version='1.0-os',
    description='For Openshift deployment',
    author='Rex',
    author_email='rexx0520@gmail.com',
    url='http://www.python.org/sigs/distutils-sig/',  
    install_requires=['Flask-SSLify','dj-database-url==0.4.1','Django==1.9.7','gunicorn==19.6.0','psycopg2==2.6.2','whitenoise==2.0.6','Flask','pycryptodome==3.4.5','requests==2.13.0','PyYAML==3.12','redis==2.10.5','freeze','pyOpenSSL'],
)