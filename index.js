'use strict';

const crypto = require('crypto');
const {send, text, json} = require('micro');

if (process.env.NODE_ENV !== 'production') {
  require('dotenv').load();
}

const webhook = data => {
  console.log(`event type: ${data.discourseEventType}`);
  console.log(`event: ${data.discourseEvent}`);
  console.log('payload:');
  console.log(data.payload);
};

module.exports = async (req, res) => {
  // Validate the instance
  const {headers} = req;
  if (headers['x-discourse-instance'] !== process.env.DISCOURSE_INSTANCE) {
    return send(res, 400, 'Invalid Discourse instance.\n');
  }

  // Validate the signature
  const raw = await text(req);
  const hmac = crypto.createHmac('sha256', process.env.DISCOURSE_WEBHOOK_SECRET);
  const hash = `sha256=${hmac.update(raw).digest('hex')}`;
  if (hash !== headers['x-discourse-event-signature']) {
    return send(res, 401, 'Invalid signature.\n');
  }

  // Process the data
  webhook({
    discourseEventType: headers['x-discourse-event-type'],
    discourseEvent: headers['x-discourse-event'],
    payload: await json(req)
  });

  return send(res, 200);
};
