import type { FastifyInstance } from 'fastify'
import { cspReportSchema } from '../schemas/csp-report.schema'

export function registerCspParser(app: FastifyInstance) {
  app.addContentTypeParser(
    'application/csp-report',
    { parseAs: 'string' },
    (req, body, done) => {
      try {
        const bodyString = typeof body === 'string' ? body : body.toString()
        const json = JSON.parse(bodyString)

        const result = cspReportSchema.safeParse(json)
        if (!result.success) {
          const error = new Error('CSP Report inválido')
          Object.assign(error, { statusCode: 400 })
          done(error, undefined)
          return
        }

        done(null, result.data)
      } catch (err) {
        const error =
          err instanceof Error
            ? err
            : new Error('Erro desconhecido ao processar o contaúdo')
        Object.assign(error, { statusCode: 400 })
        done(error, undefined)
      }
    }
  )
}
