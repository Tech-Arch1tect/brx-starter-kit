import Layout from '../components/Layout'

interface DashboardProps {
  title: string
}

export default function Dashboard({ title }: DashboardProps) {
  return (
    <Layout>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="py-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-8">{title}</h1>
          
          <div className="bg-white shadow rounded-lg p-6">
            <h2 className="text-xl font-semibold text-gray-800 mb-4">
              Welcome to brx Starter Kit
            </h2>
            <p className="text-gray-600">
              This is your dashboard. Start building your application from here.
            </p>
          </div>
        </div>
      </div>
    </Layout>
  )
}