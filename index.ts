'use strict';

import * as crypto from './src/crypto';
import * as curve from './src/curve';
import * as keyhelper from './src/keyhelper';
import ProtocolAddress = require('./src/protocol_address');
import SessionBuilder = require('./src/session_builder');
import SessionCipher = require('./src/session_cipher');
import SessionRecord = require('./src/session_record');
import * as errors from './src/errors';

const lib = {
    crypto,
    curve,
    keyhelper,
    ProtocolAddress,
    SessionBuilder,
    SessionCipher,
    SessionRecord,
    ...errors,
};

export = lib;
