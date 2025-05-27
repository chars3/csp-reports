import { app } from '../app'
import { env } from '../env'
import { registerCspParser } from '../utils/csp-parser'
import { cspReportsRoutes } from '../routes/csp-reports'
import cors from '@fastify/cors'

async function start() {
  await app.register(cors, {
    origin: ['http://localhost:5173'],
    methods: ['GET', 'POST', 'OPTIONS'],
    credentials: true,
  })

  app.register(cspReportsRoutes)

  registerCspParser(app)

  await app.listen({
    port: env.PORT,
    host: '0.0.0.0',
  })

  console.log('Server running')
}

start().catch(err => {
  console.error(err)
  process.exit(1)
})
