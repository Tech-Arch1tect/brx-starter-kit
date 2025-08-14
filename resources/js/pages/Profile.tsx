import Layout from '../components/Layout';

interface User {
  ID: number;
  username: string;
  email: string;
  CreatedAt: string;
  UpdatedAt: string;
}

interface ProfileProps {
  user: User;
  flash?: string;
}

export default function Profile({ user, flash }: ProfileProps) {
  
  return (
    <Layout>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="py-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-8">Profile</h1>
          
          {flash && (
            <div className="mb-6 p-4 text-sm text-green-700 bg-green-100 rounded-lg">
              {flash}
            </div>
          )}
          
          <div className="bg-white shadow rounded-lg">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-800">User Information</h2>
            </div>
            <div className="px-6 py-4 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Username</label>
                  <div className="mt-1 p-2 bg-gray-50 rounded-md">
                    <span className="text-gray-900">{user.username}</span>
                  </div>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Email</label>
                  <div className="mt-1 p-2 bg-gray-50 rounded-md">
                    <span className="text-gray-900">{user.email}</span>
                  </div>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Member since</label>
                  <div className="mt-1 p-2 bg-gray-50 rounded-md">
                    <span className="text-gray-900">
                      {new Date(user.CreatedAt).toLocaleDateString('en-GB', {
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric'
                      })}
                    </span>
                  </div>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700">Last updated</label>
                  <div className="mt-1 p-2 bg-gray-50 rounded-md">
                    <span className="text-gray-900">
                      {new Date(user.UpdatedAt).toLocaleDateString('en-GB', {
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric'
                      })}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}