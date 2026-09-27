// wallet.js
module.exports = function createWallet(pool) {
  const SUPPORTED_ASSETS = ['USDT', 'BTC', 'ETH'];

  async function ensureBalances(userId, client = pool) {
    for (const asset of SUPPORTED_ASSETS) {
      await client.query(
        `INSERT INTO balances (user_id, asset, amount)
         VALUES ($1, $2, 0)
         ON CONFLICT (user_id, asset) DO NOTHING`,
        [userId, asset]
      );
    }
  }

  async function getAllBalances(userId) {
    const { rows } = await pool.query(
      `SELECT asset, amount, updated_at
       FROM balances WHERE user_id = $1 ORDER BY asset`,
      [userId]
    );
    return rows.map((r) => ({
      asset: r.asset,
      amount: Number(r.amount),
      updated_at: r.updated_at,
    }));
  }

  async function getTransactions(userId, { asset, limit = 50 } = {}) {
    const params = [userId];
    let sql = `SELECT id, asset, amount, type, ref_id, metadata, created_at
               FROM wallet_transactions WHERE user_id = $1`;
    if (asset) {
      params.push(asset);
      sql += ` AND asset = $${params.length}`;
    }
    params.push(Math.min(limit, 200));
    sql += ` ORDER BY created_at DESC LIMIT $${params.length}`;
    const { rows } = await pool.query(sql, params);
    return rows.map((r) => ({ ...r, amount: Number(r.amount) }));
  }

  async function applyEntry({
    userId, asset, amount, type, refId = null, metadata = {},
  }) {
    if (!SUPPORTED_ASSETS.includes(asset)) {
      throw new Error(`Unsupported asset: ${asset}`);
    }
    if (amount === 0) throw new Error('Amount cannot be zero');

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      await client.query(
        `INSERT INTO balances (user_id, asset, amount)
         VALUES ($1, $2, 0)
         ON CONFLICT (user_id, asset) DO NOTHING`,
        [userId, asset]
      );

      const { rows } = await client.query(
        `SELECT amount FROM balances
         WHERE user_id = $1 AND asset = $2 FOR UPDATE`,
        [userId, asset]
      );

      const newAmount = Number(rows[0].amount) + Number(amount);
      if (newAmount < 0) throw new Error('Insufficient funds');

      await client.query(
        `UPDATE balances SET amount = $1, updated_at = NOW()
         WHERE user_id = $2 AND asset = $3`,
        [newAmount, userId, asset]
      );

      const { rows: txRows } = await client.query(
        `INSERT INTO wallet_transactions
           (user_id, asset, amount, type, ref_id, metadata)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, created_at`,
        [userId, asset, amount, type, refId, metadata]
      );

      await client.query('COMMIT');
      return {
        asset,
        amount: newAmount,
        txId: txRows[0].id,
        txCreatedAt: txRows[0].created_at,
      };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  return {
    SUPPORTED_ASSETS,
    ensureBalances,
    getAllBalances,
    getTransactions,
    applyEntry,
  };
};
