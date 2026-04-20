const plans = {
  starter: { usd: 9, kes: 1100 },
  pro: { usd: 29, kes: 3500 },
  team: { usd: 99, kes: 12000 },
  enterprise: { usd: 299, kes: 36000 }
};

export default function handler(req, res) {
  res.json({
    plans: Object.entries(plans).map(([id, p]) => ({ 
      id, 
      name: id.charAt(0).toUpperCase() + id.slice(1), 
      usdAmount: p.usd, 
      kesAmount: p.kes, 
      popular: id === 'pro' 
    }))
  });
}
