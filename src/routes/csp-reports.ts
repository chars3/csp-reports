import type { FastifyInstance } from 'fastify'
import * as fs from 'node:fs'
import path from 'node:path'
import type { z } from 'zod'
import { cspReportSchema } from '../schemas/csp-report.schema'

// Inferindo o tipo
export type CspReport = z.infer<typeof cspReportSchema>

interface StoredCspReport {
  timestamp: string
  userAgent: string | undefined
  report: CspReport
}

const reportsFile = path.join(__dirname, 'csp-reports.json') //

let reports: StoredCspReport[] = []

// Carrega os relatórios do arquivo, se existir
if (fs.existsSync(reportsFile)) {
  //
  const data = fs.readFileSync(reportsFile, 'utf-8') //
  reports = JSON.parse(data) //
}

export async function cspReportsRoutes(app: FastifyInstance) {
  // Recebe o relatório
  app.post('/csp-report', async (request, reply) => {
    try {
      const validatedReport = cspReportSchema.parse(request.body) //

      const reportData: StoredCspReport = {
        timestamp: new Date().toISOString(), //
        userAgent: request.headers['user-agent'], //
        report: validatedReport, //
      }

      app.log.info('Relatório de CSP recebido', reportData)

      reports.push(reportData) //

      fs.writeFileSync(reportsFile, JSON.stringify(reports, null, 2)) //

      reply.code(204).send()
    } catch (err) {
      app.log.error('Erro na validação do relatório CSP', err) //
      reply.code(400).send({ error: 'Invalid CSP report' }) //
    }
  })

  // Retorna todos os relatórios
  app.get('/csp-reports', async (request, reply) => {
    reply.send(reports) //
  })

  // Função para verificar se um report está "resolved"
  function classifyReport(report: CspReport): 'resolved' | 'pending' {
    const blockedUri = report['csp-report']['blocked-uri'] //
    // Bloqueou inline ou violou? Então ainda está pendente
    if (blockedUri === 'inline') {
      //
      return 'pending' //
    }
    // Se bloqueou externo, pode ser considerado pendente também
    if (blockedUri.startsWith('http') || blockedUri === '') {
      //
      return 'pending' //
    }
    return 'resolved' //
  }

  app.get('/csp-metrics', async (request, reply) => {
    const summary = {
      totalReports: reports.length, //
      pending: 0, //
      resolved: 0, //
    }

    const violationsBreakdown: {
      overall: {
        uniqueBlockedUris: Set<string>
        uniqueScriptSamples: Set<string>
      }
      byDirective: Record<
        string,
        {
          totalViolations: number
          pendingCount: number
          resolvedCount: number
          uniqueBlockedUris: Set<string>
          uniqueScriptSamples: Set<string>
        }
      >
    } = {
      overall: {
        uniqueBlockedUris: new Set<string>(),
        uniqueScriptSamples: new Set<string>(),
      },
      byDirective: {},
    }

    for (const item of reports) {
      //
      const reportDetails = item.report['csp-report'] //
      const directive = reportDetails['violated-directive'] //
      const blockedUri = reportDetails['blocked-uri'] //
      const scriptSample = reportDetails['script-sample'] || ''
      const status = classifyReport(item.report) //

      // Update overall summary
      if (status === 'pending') {
        //
        summary.pending += 1 //
      } else {
        summary.resolved += 1 //
      }

      // Add to overall unique sets
      violationsBreakdown.overall.uniqueBlockedUris.add(blockedUri)
      if (scriptSample) {
        violationsBreakdown.overall.uniqueScriptSamples.add(scriptSample)
      }

      // Initialize and update byDirective breakdown
      if (!violationsBreakdown.byDirective[directive]) {
        violationsBreakdown.byDirective[directive] = {
          totalViolations: 0,
          pendingCount: 0,
          resolvedCount: 0,
          uniqueBlockedUris: new Set<string>(),
          uniqueScriptSamples: new Set<string>(),
        }
      }

      const directiveMetrics = violationsBreakdown.byDirective[directive]
      directiveMetrics.totalViolations += 1
      if (status === 'pending') {
        directiveMetrics.pendingCount += 1
      } else {
        directiveMetrics.resolvedCount += 1
      }
      directiveMetrics.uniqueBlockedUris.add(blockedUri)
      if (scriptSample) {
        directiveMetrics.uniqueScriptSamples.add(scriptSample)
      }
    }

    // Convert Sets to Arrays for the response
    const responseViolationsBreakdown = {
      overall: {
        uniqueBlockedUris: Array.from(
          violationsBreakdown.overall.uniqueBlockedUris
        ),
        uniqueScriptSamples: Array.from(
          violationsBreakdown.overall.uniqueScriptSamples
        ),
      },
      byDirective: Object.fromEntries(
        Object.entries(violationsBreakdown.byDirective).map(
          ([directive, metrics]) => [
            directive,
            {
              ...metrics,
              uniqueBlockedUris: Array.from(metrics.uniqueBlockedUris),
              uniqueScriptSamples: Array.from(metrics.uniqueScriptSamples),
            },
          ]
        )
      ),
    }

    reply.send({ summary, violationsBreakdown: responseViolationsBreakdown })
  })

  app.get('/csp-reports/pending', async (request, reply) => {
    const pendingReports = reports.filter(
      //
      item => classifyReport(item.report) === 'pending' //
    )
    reply.send(pendingReports) //
  })

  app.get('/csp-reports/resolved', async (request, reply) => {
    const resolvedReports = reports.filter(
      //
      item => classifyReport(item.report) === 'resolved' //
    )
    reply.send(resolvedReports) //
  })
}
