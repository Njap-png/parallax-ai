import crypto from 'crypto';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Paystack-Signature');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

  if (req.method === 'POST' && req.headers['x-paystack-signature']) {
    const signature = req.headers['x-paystack-signature'];
    const body = JSON.stringify(req.body);
    
    const hash = crypto
      .createHmac('sha512', PAYSTACK_SECRET_KEY)
      .update(body)
      .digest('hex');
    
    if (hash !== signature) {
      console.log('[WEBHOOK] Invalid signature');
      return res.status(401).json({ error: 'Invalid signature' });
    }

    const event = req.body;
    console.log(`[WEBHOOK] Event: ${event.event}`);

    switch (event.event) {
      case 'charge.success':
        console.log(`[PAYMENT] Success: ${event.data.reference} - ${event.data.customer?.email} - Amount: ${event.data.amount}`);
        console.log(`[PAYMENT] Plan: ${event.data.metadata?.plan_id}`);
        break;
      case 'subscription.create':
        console.log(`[SUBSCRIPTION] Created: ${JSON.stringify(event.data)}`);
        break;
      case 'subscription.disable':
        console.log(`[SUBSCRIPTION] Cancelled: ${event.data?.customer}`);
        break;
      case 'invoice.create':
        console.log(`[INVOICE] Created: ${event.data?.invoice_number}`);
        break;
      case 'invoice.payment_failed':
        console.log(`[INVOICE] Failed: ${event.data?.customer}`);
        break;
      default:
        console.log(`[WEBHOOK] Unhandled event: ${event.event}`);
    }

    return res.json({ received: true });
  }

  if (req.method === 'GET') {
    return res.json({ 
      status: 'ok', 
      message: 'Paystack webhook endpoint active',
      webhook_url: 'https://parallaxdominion.vercel.app/api/payment'
    });
  }

  if (!PAYSTACK_SECRET_KEY) {
    return res.status(500).json({ error: 'Payment system not configured' });
  }

  const { action, email, plan_id, amount, currency, reference } = req.body || {};

  try {
    if (action === 'verify' && reference) {
      const response = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
        headers: { 'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`, 'Content-Type': 'application/json' }
      });
      const data = await response.json();

      if (!response.ok) {
        return res.status(400).json({ error: data.message || 'Verification failed' });
      }

      const tx = data.data;
      res.json({
        success: true,
        verified: tx.status === 'success',
        status: tx.status,
        reference: tx.reference,
        amount: tx.amount / 100,
        currency: tx.currency,
        customer: tx.customer?.email
      });
    } else {
      if (!email || !plan_id || !amount) {
        return res.status(400).json({ error: 'Email, plan_id, and amount are required' });
      }

      const response = await fetch('https://api.paystack.co/transaction/initialize', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          amount: Math.round(amount * 100),
          currency: currency === 'KES' ? 'KES' : 'USD',
          metadata: { plan_id, platform: 'parallax_dominion' }
        })
      });

      const data = await response.json();

      if (!response.ok) {
        return res.status(400).json({ error: data.message || 'Payment initialization failed' });
      }

      res.json({
        success: true,
        authorization_url: data.data.authorization_url,
        reference: data.data.reference
      });
    }
  } catch (err) {
    console.error('[PAYSTACK] Error:', err);
    res.status(500).json({ error: 'Payment processing error' });
  }
}
