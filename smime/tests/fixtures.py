# _*_ coding: utf-8 _*_
import os

import pytest


BASE_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope='module')
def base_settings():

    settings = dict()
    settings['testdata_dir'] = os.path.join(BASE_PATH, 'testdata')
    settings['carl_public_certificate'] = os.path.join(settings['testdata_dir'], 'CarlRSASelf.pem')
    settings['carl_private_certificate'] = os.path.join(settings['testdata_dir'], 'CarlPrivRSASign.pem')

    yield settings
