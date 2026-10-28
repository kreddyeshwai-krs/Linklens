import { Router } from 'express';
import { db } from '../services/db.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();

router.get('/:id', requireAuth, async (req, res, next) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const scan = await db.getScanById(req.params.id, req.user.id, isAdmin);

    if (!scan) {
      return res.status(404).json({
        error: {
          code: 'REPORT_NOT_FOUND',
          message: 'Report not found or permission denied.',
        },
      });
    }

    const report = {
      reportId: scan.id,
      generatedAt: new Date().toISOString(),
      analysisTimestamp: scan.analyzed_at,
      targetHostname: scan.normalized_hostname,
      submittedUrlRedacted: scan.submitted_url_redacted,
      registrableDomain: scan.registrable_domain,
      riskScore: scan.risk_score,
      riskCategory: scan.risk_category,
      confidenceLevel: scan.confidence_level,
      rulesetVersion: scan.ruleset_version,
      analysisMode: scan.analysis_mode,
      findings: scan.findings,
      providerResults: scan.provider_results,
      disclaimer: 'This report is a heuristic risk assessment generated for educational and security awareness purposes. It is not an absolute warranty that a destination is safe or malicious.',
    };

    res.json({ report });
  } catch (err) {
    next(err);
  }
});

export default router;

