import Layout from '../components/Layout'
import { Head } from '@inertiajs/react'

interface DashboardProps {
  title: string
  userCount: number
  currentUser: {
    id: number
    username: string
    email: string
  }
  flash?: string
}

export default function Dashboard({ title, userCount, currentUser, flash }: DashboardProps) {
  return (
    <Layout>
      <Head title={title} />
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="py-8">
          <div className="flex justify-between items-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900">{title}</h1>
            <p className="text-gray-600">Welcome back, <span className="font-semibold">{currentUser.username}</span>!</p>
          </div>
          
          {flash && (
            <div className="mb-6 p-4 text-sm text-green-700 bg-green-100 rounded-lg">
              {flash}
            </div>
          )}
          
          <div className="grid gap-6 mb-8">
            <div className="bg-white shadow rounded-lg p-6">
              <h2 className="text-xl font-semibold text-gray-800 mb-4">
                Welcome to brx Starter Kit
              </h2>
              <p className="text-gray-600 mb-4">
                This is your dashboard. Start building your application from here.
              </p>
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <h3 className="font-medium text-blue-900 mb-1">Database Connection</h3>
                <p className="text-blue-700 text-sm">
                  Successfully connected! Current user count: <span className="font-bold">{userCount}</span>
                </p>
              </div>
            </div>
            
            <div className="grid md:grid-cols-2 gap-6">
              <div className="bg-white shadow rounded-lg p-6">
                <h3 className="text-lg font-semibold text-gray-800 mb-3">Features</h3>
                <ul className="space-y-2 text-gray-600">
                  <li className="flex items-center">
                    <span className="text-green-500 mr-2">✓</span>
                    React 19 with TypeScript
                  </li>
                  <li className="flex items-center">
                    <span className="text-green-500 mr-2">✓</span>
                    Database integration (SQLite/PostgreSQL/MySQL)
                  </li>
                  <li className="flex items-center">
                    <span className="text-green-500 mr-2">✓</span>
                    Database session store
                  </li>
                  <li className="flex items-center">
                    <span className="text-green-500 mr-2">✓</span>
                    Inertia.js for SPA experience
                  </li>
                  <li className="flex items-center">
                    <span className="text-green-500 mr-2">✓</span>
                    TailwindCSS for styling
                  </li>
                </ul>
              </div>
              
              <div className="bg-white shadow rounded-lg p-6">
                <h3 className="text-lg font-semibold text-gray-800 mb-3">Next Steps</h3>
                <ul className="space-y-2 text-gray-600">
                  <li className="flex items-start">
                    <span className="text-blue-500 mr-2 mt-0.5">→</span>
                    Add authentication
                  </li>
                  <li className="flex items-start">
                    <span className="text-blue-500 mr-2 mt-0.5">→</span>
                    Create user management
                  </li>
                  <li className="flex items-start">
                    <span className="text-blue-500 mr-2 mt-0.5">→</span>
                    Build your API endpoints
                  </li>
                  <li className="flex items-start">
                    <span className="text-blue-500 mr-2 mt-0.5">→</span>
                    Add more pages & components
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  )
}