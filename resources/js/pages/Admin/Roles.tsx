import React from 'react';
import { Head } from '@inertiajs/react';
import Layout from '../../components/Layout';
import FlashMessages from '../../components/FlashMessages';

interface Permission {
  id: number;
  name: string;
  resource: string;
  action: string;
  description: string;
}

interface Role {
  id: number;
  name: string;
  description: string;
  permissions: Permission[];
}

interface Props {
  title: string;
  roles: Role[];
}

export default function AdminRoles({ title, roles }: Props) {
  return (
    <Layout>
      <Head title={title} />

      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="md:flex md:items-center md:justify-between">
          <div className="flex-1 min-w-0">
            <h2 className="text-2xl font-bold leading-7 text-gray-900 dark:text-white sm:text-3xl sm:truncate">
              {title}
            </h2>
          </div>
        </div>

        <FlashMessages />

        <div className="mt-8 grid gap-6">
          {roles.map((role) => (
            <div key={role.id} className="bg-white dark:bg-gray-800 shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white capitalize flex items-center">
                  {role.name}
                  <span
                    className={`ml-3 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                      role.name === 'admin'
                        ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200'
                        : role.name === 'moderator'
                          ? 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200'
                          : 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200'
                    }`}
                  >
                    {role.permissions.length} permission{role.permissions.length !== 1 ? 's' : ''}
                  </span>
                </h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{role.description}</p>
              </div>
              <div className="px-6 py-4">
                {role.permissions.length > 0 ? (
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">
                      Permissions:
                    </h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                      {role.permissions.map((permission) => (
                        <div
                          key={permission.id}
                          className="bg-gray-50 dark:bg-gray-700 rounded-md p-3"
                        >
                          <div className="flex items-center">
                            <code className="text-xs font-mono text-gray-800 dark:text-gray-200 bg-white dark:bg-gray-600 px-2 py-1 rounded">
                              {permission.resource}.{permission.action}
                            </code>
                          </div>
                          <p className="mt-1 text-xs text-gray-600 dark:text-gray-300">
                            {permission.description}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="text-sm text-gray-500 dark:text-gray-400">
                    No permissions assigned
                  </div>
                )}
              </div>
            </div>
          ))}

          {roles.length === 0 && (
            <div className="text-center py-12">
              <div className="text-sm text-gray-500 dark:text-gray-400">No roles found.</div>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
