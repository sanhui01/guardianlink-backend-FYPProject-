// test-push.js  (run with: node test-push.js)

import 'dotenv/config';
import mongoose from 'mongoose';

import { sendPushToTokens } from './src/utils/push.js';
import PushToken from './src/models/PushToken.js'; // to load tokens from DB

async function main() {
  try {
    // 1) connect to Mongo (same as server.js)
    await mongoose.connect(process.env.MONGODB_URI, {
      dbName: 'GuardianLink',
    });
    console.log('✅ MongoDB connected');

    // 2) Load one parent token from push_tokens collection
    const doc = await PushToken.findOne({ role: 'Parent' }).lean();
    if (!doc) {
      console.log('❌ No parent push token found in push_tokens collection');
      process.exit(0);
    }

    console.log('Using token from DB:', doc.fcmToken);

    // 3) Call sendPushToTokens with that token
    await sendPushToTokens(
      [doc.fcmToken],
      {
        title: 'TEST: Keyword Alert',
        body: 'This is a direct FCM test from test-push.js',
      },
      {
        type: 'test_keyword_alert',
      }
    );

    console.log('✔ test-push.js finished');
    process.exit(0);
  } catch (err) {
    console.error('❌ Error in test-push.js:', err);
    process.exit(1);
  }
}

main();
