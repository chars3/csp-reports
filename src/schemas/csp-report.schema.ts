import { z } from 'zod'

export const cspReportSchema = z.object({
  'csp-report': z.object({
    'document-uri': z.string().url(),
    referrer: z.string().optional(),
    'violated-directive': z.string(),
    'effective-directive': z.string().optional(),
    'original-policy': z.string(),
    'blocked-uri': z.string(),
    'status-code': z.number().optional(),
    'script-sample': z.string().optional(),
  }),
})
