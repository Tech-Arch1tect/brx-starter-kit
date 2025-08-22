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

interface Props {
  title: string;
  permissions: Permission[];
}

export default function AdminPermissions({ title, permissions }: Props) {
  // Group permissions by resource
  const permissionsByResource = permissions.reduce(
    (acc, permission) => {
      const resource = permission.resource;
      if (!acc[resource]) {
        acc[resource] = [];
      }
      acc[resource].push(permission);
      return acc;
    },
    {} as Record<string, Permission[]>
  );

  const getActionColor = (action: string) => {
    switch (action.toLowerCase()) {
      case 'create':
        return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200';
      case 'read':
        return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200';
      case 'update':
        return 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200';
      case 'delete':
        return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200';
      case 'access':
        return 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200';
      default:
        return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200';
    }
  };

  return (
    <Layout>
      <Head title={title} />

      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="md:flex md:items-center md:justify-between">
          <div className="flex-1 min-w-0">
            <h2 className="text-2xl font-bold leading-7 text-gray-900 dark:text-white sm:text-3xl sm:truncate">
              {title}
            </h2>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              {permissions.length} permission{permissions.length !== 1 ? 's' : ''} across{' '}
              {Object.keys(permissionsByResource).length} resource
              {Object.keys(permissionsByResource).length !== 1 ? 's' : ''}
            </p>
          </div>
        </div>

        <FlashMessages />

        <div className="mt-8 space-y-8">
          {Object.entries(permissionsByResource).map(([resource, resourcePermissions]) => (
            <div key={resource} className="bg-white dark:bg-gray-800 shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white capitalize flex items-center">
                  {resource}
                  <span className="ml-3 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-100 dark:bg-indigo-900 text-indigo-800 dark:text-indigo-200">
                    {resourcePermissions.length} permission
                    {resourcePermissions.length !== 1 ? 's' : ''}
                  </span>
                </h3>
              </div>
              <div className="px-6 py-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                  {resourcePermissions.map((permission) => (
                    <div
                      key={permission.id}
                      className="border border-gray-200 dark:border-gray-600 rounded-lg p-4"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <code className="text-sm font-mono text-gray-800 dark:text-gray-200 bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
                          {permission.name}
                        </code>
                        <span
                          className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getActionColor(permission.action)}`}
                        >
                          {permission.action}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-300">
                        {permission.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}

          {permissions.length === 0 && (
            <div className="text-center py-12">
              <div className="text-sm text-gray-500 dark:text-gray-400">No permissions found.</div>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
