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

const reportsFile = path.join(__dirname, 'csp-reports.json')

let reports: StoredCspReport[] = []

// Carrega os relatórios do arquivo, se existir
if (fs.existsSync(reportsFile)) {
  const data = fs.readFileSync(reportsFile, 'utf-8')
  reports = JSON.parse(data)
}

export async function cspReportsRoutes(app: FastifyInstance) {
  // Recebe o relatório
  app.post('/csp-report', async (request, reply) => {
    try {
      const validatedReport = cspReportSchema.parse(request.body)

      const reportData: StoredCspReport = {
        timestamp: new Date().toISOString(),
        userAgent: request.headers['user-agent'],
        report: validatedReport,
      }

      app.log.info('Relatório de CSP recebido', reportData)

      reports.push(reportData)

      fs.writeFileSync(reportsFile, JSON.stringify(reports, null, 2))

      reply.code(204).send()
    } catch (err) {
      app.log.error('Erro na validação do relatório CSP', err)
      reply.code(400).send({ error: 'Invalid CSP report' })
    }
  })

  // Retorna todos os relatórios
  app.get('/csp-reports', async (request, reply) => {
    reply.send(reports)
  })

  // Função para verificar se um report está "resolved"
  function classifyReport(report: CspReport): 'resolved' | 'pending' {
    const blockedUri = report['csp-report']['blocked-uri']
    // Bloqueou inline ou violou? Então ainda está pendente
    if (blockedUri === 'inline') {
      return 'pending'
    }
    // Se bloqueou externo, pode ser considerado pendente também
    if (blockedUri.startsWith('http') || blockedUri === '') {
      return 'pending'
    }
    return 'resolved'
  }

  app.get('/csp-metrics', async (request, reply) => {
    const summary = {
      totalReports: reports.length,
      pending: 0,
      resolved: 0,
      byDirective: {} as Record<string, { pending: number; resolved: number }>,
    }

    for (const item of reports) {
      const report = item.report['csp-report']
      const directive = report['violated-directive']
      const status = classifyReport(item.report)

      if (!summary.byDirective[directive]) {
        summary.byDirective[directive] = { pending: 0, resolved: 0 }
      }

      if (status === 'pending') {
        summary.pending += 1
        summary.byDirective[directive].pending += 1
      } else {
        summary.resolved += 1
        summary.byDirective[directive].resolved += 1
      }
    }

    reply.send({ summary })
  })

  app.get('/csp-reports/pending', async (request, reply) => {
    const pendingReports = reports.filter(
      item => classifyReport(item.report) === 'pending'
    )
    reply.send(pendingReports)
  })

  app.get('/csp-reports/resolved', async (request, reply) => {
    const resolvedReports = reports.filter(
      item => classifyReport(item.report) === 'resolved'
    )
    reply.send(resolvedReports)
  })
}
