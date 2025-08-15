import { Link, usePage, router } from '@inertiajs/react';
import { ReactNode } from 'react';

interface LayoutProps {
  children: ReactNode;
}

interface User {
  id: number;
  username: string;
  email: string;
}

export default function Layout({ children }: LayoutProps) {
  const { url, props } = usePage();
  const user = props.currentUser as User | undefined;
  const csrfToken = props.csrfToken as string | undefined;

  const navigation = [
    { name: 'Dashboard', href: '/' },
  ];

  const handleLogout = () => {
    router.post('/auth/logout', {}, {
      headers: {
        'X-CSRF-Token': csrfToken || '',
      },
    });
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center space-x-8">
              <Link href="/" className="flex-shrink-0">
                <h1 className="text-xl font-bold text-gray-900">brx Starter Kit</h1>
              </Link>
              {user && (
                <div className="hidden sm:flex sm:space-x-8">
                  {navigation.map((item) => (
                    <Link
                      key={item.name}
                      href={item.href}
                      className={`text-gray-600 hover:text-gray-900 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                        url === item.href ? 'text-blue-600 bg-blue-50' : ''
                      }`}
                    >
                      {item.name}
                    </Link>
                  ))}
                </div>
              )}
            </div>
            
            {user ? (
              <div className="flex items-center space-x-4">
                <Link 
                  href="/profile" 
                  className="text-gray-600 hover:text-gray-900 text-sm font-medium"
                >
                  {user.username}
                </Link>
                <button
                  onClick={handleLogout}
                  className="bg-red-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-red-700 transition-colors"
                >
                  Logout
                </button>
              </div>
            ) : (
              <div className="flex items-center space-x-4">
                <Link 
                  href="/auth/login" 
                  className="text-gray-600 hover:text-gray-900 text-sm font-medium"
                >
                  Login
                </Link>
                <Link 
                  href="/auth/register" 
                  className="bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700 transition-colors"
                >
                  Register
                </Link>
              </div>
            )}
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        {children}
      </main>

      <footer className="bg-white border-t border-gray-200 mt-12">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <p className="text-center text-gray-500 text-sm">
            Built with brx, Inertia.js, and React
          </p>
        </div>
      </footer>
    </div>
  );
}