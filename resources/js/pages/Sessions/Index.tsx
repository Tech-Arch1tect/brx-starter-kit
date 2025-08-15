import Layout from '../../components/Layout'
import { Head, useForm, usePage, router } from '@inertiajs/react'
import { formatDistanceToNow } from 'date-fns'
import {
  DevicePhoneMobileIcon,
  DeviceTabletIcon,
  ComputerDesktopIcon,
  CpuChipIcon,
  GlobeAltIcon,
  FireIcon,
  CommandLineIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline'

interface Session {
  id: number
  current: boolean
  ip_address: string
  location: string
  browser: string
  os: string
  device_type: string
  device: string
  mobile: boolean
  tablet: boolean
  desktop: boolean
  bot: boolean
  created_at: string
  last_used: string
  expires_at: string
}

interface SessionsProps {
  sessions: Session[]
  flash?: string
}

export default function SessionsIndex({ sessions, flash }: SessionsProps) {
  const { processing } = useForm()
  const { props } = usePage()
  const csrfToken = props.csrfToken as string | undefined

  const revokeSession = (sessionId: number) => {
    if (confirm('Are you sure you want to revoke this session? You will be logged out from that device.')) {
      router.post('/sessions/revoke', {
        session_id: sessionId,
      }, {
        headers: {
          'X-CSRF-Token': csrfToken || '',
        },
        preserveState: true,
      })
    }
  }

  const revokeAllOthers = () => {
    if (confirm('Are you sure you want to revoke all other sessions? You will be logged out from all other devices.')) {
      router.post('/sessions/revoke-all-others', {}, {
        headers: {
          'X-CSRF-Token': csrfToken || '',
        },
        preserveState: true,
      })
    }
  }

  const formatDate = (dateString: string) => {
    return formatDistanceToNow(new Date(dateString), { addSuffix: true })
  }

  const getDeviceIcon = (session: Session) => {
    const iconClass = "h-8 w-8 text-gray-600"
    
    // Return icon based on device type and browser
    if (session.bot) return <CpuChipIcon className={iconClass} />
    if (session.mobile) return <DevicePhoneMobileIcon className={iconClass} />
    if (session.tablet) return <DeviceTabletIcon className={iconClass} />
    
    // Desktop browser icons
    const browser = session.browser.toLowerCase()
    if (browser.includes('chrome')) return <GlobeAltIcon className={iconClass} />
    if (browser.includes('firefox')) return <FireIcon className={iconClass} />
    if (browser.includes('safari')) return <CommandLineIcon className={iconClass} />
    if (browser.includes('edge')) return <ShieldCheckIcon className={iconClass} />
    if (browser.includes('opera')) return <ExclamationTriangleIcon className={iconClass} />
    
    return <ComputerDesktopIcon className={iconClass} />
  }

  const getDeviceTypeColor = (session: Session) => {
    if (session.bot) return 'text-purple-600 bg-purple-100'
    if (session.mobile) return 'text-blue-600 bg-blue-100'
    if (session.tablet) return 'text-green-600 bg-green-100'
    return 'text-gray-600 bg-gray-100'
  }

  return (
    <Layout>
      <Head title="Active Sessions" />
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="py-8">
          <div className="flex justify-between items-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900">Active Sessions</h1>
            {sessions.filter(s => !s.current).length > 0 && (
              <button
                onClick={revokeAllOthers}
                disabled={processing}
                className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50"
              >
                Revoke All Others
              </button>
            )}
          </div>

          {flash && (
            <div className="mb-6 p-4 text-sm text-green-700 bg-green-100 rounded-lg">
              {flash}
            </div>
          )}

          <div className="bg-white shadow overflow-hidden sm:rounded-md">
            <ul className="divide-y divide-gray-200">
              {sessions.map((session) => (
                <li key={session.id} className="px-6 py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <div className="flex-shrink-0">
                        {getDeviceIcon(session)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center space-x-2 mb-2">
                          <p className="text-sm font-medium text-gray-900">
                            {session.browser}
                          </p>
                          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getDeviceTypeColor(session)}`}>
                            {session.device_type}
                          </span>
                          {session.current && (
                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                              Current Session
                            </span>
                          )}
                        </div>
                        <div className="mt-1 text-sm text-gray-500 space-y-1">
                          <p>
                            <span className="font-medium">Operating System:</span> {session.os}
                          </p>
                          <p>
                            <span className="font-medium">Device:</span> {session.device}
                          </p>
                          <p>
                            <span className="font-medium">Location:</span> {session.location}
                          </p>
                          <p>
                            <span className="font-medium">IP Address:</span> {session.ip_address}
                          </p>
                          <p>
                            <span className="font-medium">Last Active:</span> {formatDate(session.last_used)}
                          </p>
                          <p>
                            <span className="font-medium">Created:</span> {formatDate(session.created_at)}
                          </p>
                        </div>
                      </div>
                    </div>
                    
                    {!session.current && (
                      <div className="flex-shrink-0">
                        <button
                          onClick={() => revokeSession(session.id)}
                          disabled={processing}
                          className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-red-700 bg-red-100 hover:bg-red-200 disabled:opacity-50"
                        >
                          Revoke
                        </button>
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </div>

          {sessions.length === 0 && (
            <div className="text-center py-12">
              <div className="text-gray-500">
                <p className="text-lg">No active sessions found.</p>
                <p className="text-sm mt-2">This might indicate a configuration issue with session tracking.</p>
              </div>
            </div>
          )}

          <div className="mt-8 bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex">
              <div className="flex-shrink-0">
                <InformationCircleIcon className="h-5 w-5 text-blue-400" />
              </div>
              <div className="ml-3">
                <p className="text-sm text-blue-700">
                  <strong>Security Note:</strong> If you see any sessions you don't recognise, revoke them immediately. 
                  You can also revoke all other sessions if you suspect unauthorised access.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  )
}