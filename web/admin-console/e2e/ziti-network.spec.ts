import { test, expect } from '@playwright/test';

test.describe('Ziti Network Page', () => {
  test.beforeEach(async ({ page }) => {
    // Mock Ziti status API
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          enabled: true,
          sdk_ready: true,
          controller_reachable: true,
          services_count: 5,
          identities_count: 10,
        }),
      });
    });

    // Mock fabric overview
    await page.route('**/api/v1/access/ziti/fabric/overview', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          controller_online: true,
          router_count: 3,
          service_count: 5,
          identity_count: 10,
          healthy_routers: 2,
          unhealthy_routers: 1,
        }),
      });
    });

    // Mock fabric routers
    await page.route('**/api/v1/access/ziti/fabric/routers', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 'router-1', name: 'edge-router-1', is_online: true, hostname: 'router1.example.com', fingerprint: 'abc123def456', created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-20T00:00:00Z' },
          { id: 'router-2', name: 'edge-router-2', is_online: true, hostname: 'router2.example.com', fingerprint: 'xyz789uvw012', created_at: '2024-01-05T00:00:00Z', updated_at: '2024-01-20T00:00:00Z' },
          { id: 'router-3', name: 'edge-router-3', is_online: false, hostname: 'router3.example.com', fingerprint: 'mno345pqr678', created_at: '2024-01-10T00:00:00Z', updated_at: '2024-01-15T00:00:00Z' },
        ]),
      });
    });

    // Mock services
    await page.route('**/api/v1/access/ziti/services', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            services: [
              { id: '1', ziti_id: 'svc-001', name: 'web-service', description: 'Web frontend', protocol: 'tcp', host: '10.0.0.1', port: 443, enabled: true, created_at: '2024-01-01T00:00:00Z' },
              { id: '2', ziti_id: 'svc-002', name: 'api-service', description: 'Backend API', protocol: 'tcp', host: '10.0.0.2', port: 8080, enabled: true, created_at: '2024-01-05T00:00:00Z' },
              { id: '3', ziti_id: 'svc-003', name: 'database', description: 'PostgreSQL', protocol: 'tcp', host: '10.0.0.3', port: 5432, enabled: false, created_at: '2024-01-10T00:00:00Z' },
            ],
          }),
        });
      } else if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-service-id',
            ziti_id: 'svc-new',
            ...body,
            enabled: true,
            created_at: new Date().toISOString(),
          }),
        });
      }
    });

    // Mock identities
    await page.route('**/api/v1/access/ziti/identities', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            identities: [
              { id: '1', ziti_id: 'id-001', name: 'user-john', identity_type: 'User', user_id: 'user-1', enrolled: true, attributes: ['users', 'developers'], created_at: '2024-01-01T00:00:00Z' },
              { id: '2', ziti_id: 'id-002', name: 'device-laptop', identity_type: 'Device', enrolled: true, attributes: ['devices', 'trusted'], created_at: '2024-01-05T00:00:00Z' },
              { id: '3', ziti_id: 'id-003', name: 'service-api', identity_type: 'Service', enrolled: false, attributes: ['services'], created_at: '2024-01-10T00:00:00Z' },
            ],
          }),
        });
      } else if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-identity-id',
            ziti_id: 'id-new',
            ...body,
            enrolled: false,
            created_at: new Date().toISOString(),
          }),
        });
      }
    });

    // Mock identity enrollment JWT
    await page.route('**/api/v1/access/ziti/identities/*/enrollment-jwt', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          jwt: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.mock-enrollment-jwt-content.signature',
        }),
      });
    });

    // Mock delete endpoints
    await page.route('**/api/v1/access/ziti/services/*', async (route) => {
      if (route.request().method() === 'DELETE') {
        await route.fulfill({ status: 204 });
      }
    });

    await page.route('**/api/v1/access/ziti/identities/*', async (route) => {
      if (route.request().method() === 'DELETE') {
        await route.fulfill({ status: 204 });
      }
    });
  });

  test('should display Ziti Network page', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.locator('h1:has-text("Ziti Network")')).toBeVisible();
    await expect(page.locator('text=Manage your OpenZiti zero-trust network overlay')).toBeVisible();
  });

  test('should show connection status', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.locator('text=Connected')).toBeVisible();
  });

  test('should display services and identities count badges', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.locator('text=5 services')).toBeVisible();
    await expect(page.locator('text=10 identities')).toBeVisible();
  });

  test('should have all navigation tabs', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.getByRole('tab', { name: /overview/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /services/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /identities/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /security/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /remote access/i })).toBeVisible();
  });
});

test.describe('Ziti Overview Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 5, identities_count: 10 }),
      });
    });

    await page.route('**/api/v1/access/ziti/fabric/overview', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ controller_online: true, router_count: 3, service_count: 5, identity_count: 10, healthy_routers: 2, unhealthy_routers: 1 }),
      });
    });

    await page.route('**/api/v1/access/ziti/fabric/routers', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', name: 'edge-router-1', is_online: true, hostname: 'router1.example.com', fingerprint: 'abc123', created_at: '2024-01-01T00:00:00Z' },
          { id: '2', name: 'edge-router-2', is_online: false, hostname: 'router2.example.com', fingerprint: 'def456', created_at: '2024-01-05T00:00:00Z' },
        ]),
      });
    });
  });

  test('should display controller status', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.locator('text=Controller')).toBeVisible();
    await expect(page.locator('text=Online').first()).toBeVisible();
  });

  test('should display router count', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.getByRole('heading', { name: 'Routers', exact: true })).toBeVisible();
    await expect(page.locator('text=2 healthy, 1 unhealthy')).toBeVisible();
  });

  test('should display edge routers table', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.getByRole('heading', { name: 'Edge Routers', exact: true })).toBeVisible();
    await expect(page.locator('text=edge-router-1')).toBeVisible();
    await expect(page.locator('text=edge-router-2')).toBeVisible();
  });

  test('should show router online/offline status', async ({ page }) => {
    await page.goto('/ziti-network');

    // Check for Online badge
    await expect(page.locator('td >> text=Online').first()).toBeVisible();
    // Check for Offline badge
    await expect(page.locator('td >> text=Offline')).toBeVisible();
  });

  test('should have health check button', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.getByRole('button', { name: /health check/i })).toBeVisible();
  });

  test('should have reconnect button', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.getByRole('button', { name: /reconnect/i })).toBeVisible();
  });
});

test.describe('Ziti Services Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 3, identities_count: 5 }) });
    });

    await page.route('**/api/v1/access/ziti/services', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            services: [
              { id: '1', ziti_id: 'svc-001', name: 'web-service', description: 'Web frontend', protocol: 'tcp', host: '10.0.0.1', port: 443, enabled: true, created_at: '2024-01-01T00:00:00Z' },
              { id: '2', ziti_id: 'svc-002', name: 'api-service', description: 'Backend API', protocol: 'tcp', host: '10.0.0.2', port: 8080, enabled: true, created_at: '2024-01-05T00:00:00Z' },
            ],
          }),
        });
      } else if (route.request().method() === 'POST') {
        await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ id: 'new', ziti_id: 'svc-new', name: 'new-service', created_at: new Date().toISOString() }) });
      }
    });

    await page.route('**/api/v1/access/ziti/services/*', async (route) => {
      if (route.request().method() === 'DELETE') {
        await route.fulfill({ status: 204 });
      }
    });
  });

  test('should display services tab content', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await expect(page.locator('text=web-service')).toBeVisible();
    await expect(page.locator('text=api-service')).toBeVisible();
  });

  test('should have Add Service button', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await expect(page.getByRole('button', { name: /add service/i })).toBeVisible();
  });

  test('should open create service modal', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await page.getByRole('button', { name: /add service/i }).click();

    await expect(page.locator('text=Create Ziti Service')).toBeVisible();
    await expect(page.getByPlaceholder('internal-app').first()).toBeVisible();
    await expect(page.getByRole('spinbutton')).toBeVisible(); // Port field
  });

  test('should create service successfully', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await page.getByRole('button', { name: /add service/i }).click();

    // Use placeholder selectors - 'internal-app' is used for both name and host
    const nameInput = page.getByPlaceholder('internal-app').first();
    const hostInput = page.getByPlaceholder('internal-app').nth(1);
    const portInput = page.getByRole('spinbutton');

    await nameInput.fill('new-service');
    await hostInput.fill('192.168.1.100');
    await portInput.fill('3000');

    await page.getByRole('button', { name: /create service/i }).click();

    // Success toast
    await expect(page.locator('text=Service created').first()).toBeVisible();
  });

  test('should have search input for services', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await expect(page.getByPlaceholder(/search services/i)).toBeVisible();
  });

  test('should show service details', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    // Check service info is displayed
    await expect(page.locator('text=10.0.0.1').or(page.locator('text=443'))).toBeVisible();
  });

  test('should create internal SSH server service with IP 10.0.0.10', async ({ page }) => {
    // Override POST mock to capture and verify SSH service creation
    await page.route('**/api/v1/access/ziti/services', async (route) => {
      if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        // Verify the request body contains expected SSH service data
        expect(body.name).toBe('internal-ssh-server');
        expect(body.host).toBe('10.0.0.10');
        expect(body.port).toBe(22);
        expect(body.protocol).toBe('tcp');

        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'ssh-service-id',
            ziti_id: 'svc-ssh-001',
            name: 'internal-ssh-server',
            description: 'Internal SSH Server',
            protocol: 'tcp',
            host: '10.0.0.10',
            port: 22,
            enabled: true,
            created_at: new Date().toISOString(),
          }),
        });
      } else {
        // Handle GET requests with existing services plus new SSH service
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            services: [
              { id: '1', ziti_id: 'svc-001', name: 'web-service', description: 'Web frontend', protocol: 'tcp', host: '10.0.0.1', port: 443, enabled: true, created_at: '2024-01-01T00:00:00Z' },
              { id: '2', ziti_id: 'svc-002', name: 'api-service', description: 'Backend API', protocol: 'tcp', host: '10.0.0.2', port: 8080, enabled: true, created_at: '2024-01-05T00:00:00Z' },
            ],
          }),
        });
      }
    });

    await page.goto('/ziti-network');

    // Navigate to services tab
    await page.getByRole('tab', { name: /services/i }).click();

    // Click Add Service button
    await page.getByRole('button', { name: /add service/i }).click();

    // Wait for create service modal to appear
    await expect(page.locator('text=Create Ziti Service')).toBeVisible();

    // Fill in the SSH service details using placeholder selectors
    const nameInput = page.getByPlaceholder('internal-app').first();
    const descInput = page.getByPlaceholder('Optional description');
    const hostInput = page.getByPlaceholder('internal-app').nth(1);
    const portInput = page.getByRole('spinbutton');

    await nameInput.fill('internal-ssh-server');
    await descInput.fill('Internal SSH Server');
    await hostInput.fill('10.0.0.10');
    await portInput.fill('22');

    // Protocol is already set to TCP by default

    // Submit the form
    await page.getByRole('button', { name: /create service/i }).click();

    // Verify success message
    await expect(page.locator('text=Service created').first()).toBeVisible();
  });

  test('should validate SSH service port 22 is valid', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await page.getByRole('button', { name: /add service/i }).click();

    await expect(page.locator('text=Create Ziti Service')).toBeVisible();

    // Use placeholder selectors
    const nameInput = page.getByPlaceholder('internal-app').first();
    const hostInput = page.getByPlaceholder('internal-app').nth(1);
    const portInput = page.getByRole('spinbutton');

    // Fill with SSH standard port
    await nameInput.fill('ssh-test-service');
    await hostInput.fill('10.0.0.10');
    await portInput.fill('22');

    // Verify port field accepts value 22
    await expect(portInput).toHaveValue('22');
  });

  test('should display SSH service in services list after creation', async ({ page }) => {
    // Mock services list including the SSH server
    await page.route('**/api/v1/access/ziti/services', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            services: [
              { id: '1', ziti_id: 'svc-001', name: 'web-service', description: 'Web frontend', protocol: 'tcp', host: '10.0.0.1', port: 443, enabled: true, created_at: '2024-01-01T00:00:00Z' },
              { id: '2', ziti_id: 'svc-002', name: 'api-service', description: 'Backend API', protocol: 'tcp', host: '10.0.0.2', port: 8080, enabled: true, created_at: '2024-01-05T00:00:00Z' },
              { id: '3', ziti_id: 'svc-ssh-001', name: 'internal-ssh-server', description: 'Internal SSH Server', protocol: 'tcp', host: '10.0.0.10', port: 22, enabled: true, created_at: '2024-01-15T00:00:00Z' },
            ],
          }),
        });
      }
    });

    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    // Verify SSH service is displayed
    await expect(page.locator('text=internal-ssh-server')).toBeVisible();
    await expect(page.locator('text=10.0.0.10')).toBeVisible();
  });
});

test.describe('Ziti Identities Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 3, identities_count: 3 }) });
    });

    await page.route('**/api/v1/access/ziti/identities', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            identities: [
              { id: '1', ziti_id: 'id-001', name: 'user-john', identity_type: 'User', user_id: 'user-1', enrolled: true, attributes: ['users'], created_at: '2024-01-01T00:00:00Z' },
              { id: '2', ziti_id: 'id-002', name: 'device-laptop', identity_type: 'Device', enrolled: true, attributes: ['devices'], created_at: '2024-01-05T00:00:00Z' },
              { id: '3', ziti_id: 'id-003', name: 'service-api', identity_type: 'Service', enrolled: false, attributes: ['services'], created_at: '2024-01-10T00:00:00Z' },
            ],
          }),
        });
      } else if (route.request().method() === 'POST') {
        await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ id: 'new', ziti_id: 'id-new', name: 'new-identity', enrolled: false, created_at: new Date().toISOString() }) });
      }
    });

    await page.route('**/api/v1/access/ziti/identities/*/enrollment-jwt', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ jwt: 'mock-enrollment-jwt' }) });
    });
  });

  test('should display identities tab content', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    await expect(page.locator('text=user-john')).toBeVisible();
    await expect(page.locator('text=device-laptop')).toBeVisible();
    await expect(page.locator('text=service-api')).toBeVisible();
  });

  test('should show identity types', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    // Check that at least one identity type is visible in the table
    await expect(page.locator('td:has-text("User")').or(page.locator('td:has-text("Device")').or(page.locator('td:has-text("Service")'))).first()).toBeVisible();
  });

  test('should have Add Identity button', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    await expect(page.getByRole('button', { name: /add identity/i })).toBeVisible();
  });

  test('should open create identity modal', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    await page.getByRole('button', { name: /add identity/i }).click();

    await expect(page.locator('text=Create Ziti Identity')).toBeVisible();
    await expect(page.getByPlaceholder('john-laptop')).toBeVisible();
  });

  test('should show enrollment status', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    // Check that at least one enrolled badge is visible
    await expect(page.getByRole('cell', { name: 'Enrolled' }).first()).toBeVisible();
  });

  test('should have search input for identities', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    await expect(page.getByPlaceholder(/search identities/i)).toBeVisible();
  });
});

test.describe('Ziti Network Status Conditions', () => {
  test('should show disconnected status when controller is unreachable', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          enabled: true,
          sdk_ready: false,
          controller_reachable: false,
          controller_error: 'Connection refused',
          services_count: 0,
          identities_count: 0,
        }),
      });
    });

    await page.goto('/ziti-network');

    await expect(page.locator('text=Disconnected')).toBeVisible();
  });

  test('should show empty state when no services exist', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 0, identities_count: 0 }) });
    });

    await page.route('**/api/v1/access/ziti/services', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ services: [] }) });
    });

    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await expect(page.locator('text=No services').or(page.locator('text=No Ziti services'))).toBeVisible();
  });

  test('should show empty state when no identities exist', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 0, identities_count: 0 }) });
    });

    await page.route('**/api/v1/access/ziti/identities', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ identities: [] }) });
    });

    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    await expect(page.locator('text=No identities').or(page.locator('text=No Ziti identities'))).toBeVisible();
  });

  test('should show empty state when no routers exist', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 0, identities_count: 0 }) });
    });

    await page.route('**/api/v1/access/ziti/fabric/overview', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ controller_online: true, router_count: 0, service_count: 0, identity_count: 0, healthy_routers: 0, unhealthy_routers: 0 }) });
    });

    await page.route('**/api/v1/access/ziti/fabric/routers', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
    });

    await page.goto('/ziti-network');

    await expect(page.locator('text=No edge routers')).toBeVisible();
  });
});

test.describe('Ziti Security Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 5, identities_count: 10 }) });
    });

    // Mock service policies
    await page.route('**/api/v1/access/ziti/fabric/service-policies', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 'pol-1', name: 'openidx-dial-web', type: 'Dial', serviceRoles: ['#web'], identityRoles: ['#access-proxy-clients'] },
          { id: 'pol-2', name: 'openidx-bind-web', type: 'Bind', serviceRoles: ['#web'], identityRoles: ['#access-proxy-clients'] },
          { id: 'pol-3', name: 'allow-engineering-api', type: 'Dial', serviceRoles: ['#api-service'], identityRoles: ['#engineering'] },
        ]),
      });
    });

    // Mock service policy CRUD
    await page.route('**/api/v1/access/ziti/service-policies', async (route) => {
      if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ id: 'new-pol', ziti_id: 'ziti-pol-new', ...body }),
        });
      }
    });

    await page.route('**/api/v1/access/ziti/service-policies/*', async (route) => {
      if (route.request().method() === 'DELETE') {
        await route.fulfill({ status: 204 });
      } else if (route.request().method() === 'PUT') {
        const body = route.request().postDataJSON();
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ id: route.request().url().split('/').pop(), ...body }) });
      }
    });

    // Note: API uses /posture/checks (not /posture-checks)
    await page.route('**/api/v1/access/ziti/posture/checks*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', name: 'OS Check', check_type: 'OS', enabled: true, severity: 'high', created_at: '2024-01-01T00:00:00Z' },
          { id: '2', name: 'MFA Check', check_type: 'MFA', enabled: true, severity: 'critical', created_at: '2024-01-05T00:00:00Z' },
        ]),
      });
    });

    await page.route('**/api/v1/access/ziti/certificates*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', name: 'Root CA', cert_type: 'ca', subject: 'CN=Root CA', issuer: 'CN=Root CA', fingerprint: 'abc123', not_before: '2024-01-01', not_after: '2026-01-01', auto_renew: true, status: 'valid', days_until_expiry: 365 },
        ]),
      });
    });
  });

  test('should display security tab content', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /security/i }).click();

    // Check for posture checks section
    await expect(page.locator('text=Posture Checks').or(page.locator('text=Security Policies'))).toBeVisible();
  });

  test('should show posture checks', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /security/i }).click();

    // Use first() for strict mode since both checks are visible
    await expect(page.getByRole('cell', { name: 'OS Check' }).or(page.getByRole('cell', { name: 'MFA Check' })).first()).toBeVisible();
  });

  test('should show certificates section', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /security/i }).click();

    // Use first() for strict mode
    await expect(page.getByRole('cell', { name: 'Root CA', exact: true }).or(page.getByRole('button', { name: 'Certificates' })).first()).toBeVisible();
  });

  test('should display service policies section with system and custom policies', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /security/i }).click();

    // Service Policies section should be visible
    await expect(page.locator('text=Service Policies').first()).toBeVisible();

    // Should show system policies (with lock icon via openidx- prefix)
    await expect(page.locator('text=openidx-dial-web')).toBeVisible();
    await expect(page.locator('text=openidx-bind-web')).toBeVisible();

    // Should show custom policy
    await expect(page.locator('text=allow-engineering-api')).toBeVisible();

    // Should show Dial and Bind badges
    await expect(page.getByRole('cell').filter({ hasText: 'Dial' }).first()).toBeVisible();
    await expect(page.getByRole('cell').filter({ hasText: 'Bind' }).first()).toBeVisible();

    // Should show role badges
    await expect(page.locator('text=#web').first()).toBeVisible();
    await expect(page.locator('text=#engineering').first()).toBeVisible();
  });

  test('should have Add Policy button in service policies section', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /security/i }).click();

    await expect(page.getByRole('button', { name: /add policy/i })).toBeVisible();
  });

  test('should open create policy dialog and fill form', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /security/i }).click();

    await page.getByRole('button', { name: /add policy/i }).click();

    await expect(page.locator('text=Create Service Policy')).toBeVisible();

    // Fill form
    await page.getByPlaceholder('allow-engineering-gitlab').fill('test-finance-dial');

    // Type selector should default to Dial
    const typeSelect = page.locator('form select').first();
    await expect(typeSelect).toHaveValue('Dial');

    // Fill roles
    await page.getByPlaceholder('#gitlab, #internal-apps').fill('#test-service');
    await page.getByPlaceholder('#engineering, #vpn-users').fill('#finance');

    // Submit
    await page.getByRole('button', { name: /create policy/i }).click();
    await expect(page.locator('text=Service policy created').first()).toBeVisible();
  });

  test('should not show edit/delete menu on system policies', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /security/i }).click();

    // System policy row (openidx-dial-web) should NOT have a dropdown menu button
    const systemRow = page.locator('tr', { hasText: 'openidx-dial-web' });
    await expect(systemRow).toBeVisible();
    // System rows should not have the MoreHorizontal dropdown trigger
    const menuBtn = systemRow.locator('button[role="trigger"], button:has(svg)').last();
    // The row should not have the dropdown — check there's no MoreHorizontal
    const rowButtons = await systemRow.locator('button').count();
    expect(rowButtons).toBe(0);

    // Custom policy row should have dropdown
    const customRow = page.locator('tr', { hasText: 'allow-engineering-api' });
    await expect(customRow).toBeVisible();
    const customButtons = await customRow.locator('button').count();
    expect(customButtons).toBeGreaterThan(0);
  });
});

test.describe('Ziti Identity Attributes', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 3, identities_count: 3 }) });
    });

    await page.route('**/api/v1/access/ziti/identities', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            identities: [
              { id: '1', ziti_id: 'id-001', name: 'user-john', identity_type: 'User', user_id: 'user-1', enrolled: true, attributes: ['engineering', 'vpn-users'], created_at: '2024-01-01T00:00:00Z' },
              { id: '2', ziti_id: 'id-002', name: 'device-laptop', identity_type: 'Device', enrolled: true, attributes: [], created_at: '2024-01-05T00:00:00Z' },
            ],
          }),
        });
      }
    });

    await page.route('**/api/v1/access/ziti/identities/*/attributes', async (route) => {
      if (route.request().method() === 'PATCH') {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ id: '1', ziti_id: 'id-001', attributes: body.attributes, message: 'identity attributes updated' }),
        });
      }
    });
  });

  test('should display role attributes as badges in identities table', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    // user-john should show engineering and vpn-users badges
    const johnRow = page.locator('tr', { hasText: 'user-john' });
    await expect(johnRow).toBeVisible();
    await expect(johnRow.locator('text=engineering')).toBeVisible();
    await expect(johnRow.locator('text=vpn-users')).toBeVisible();

    // device-laptop should show "none"
    const laptopRow = page.locator('tr', { hasText: 'device-laptop' });
    await expect(laptopRow).toBeVisible();
    await expect(laptopRow.locator('text=none')).toBeVisible();
  });

  test('should have Roles column header', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    await expect(page.locator('th:has-text("Roles")')).toBeVisible();
  });

  test('should open edit attributes dialog from dropdown menu', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    // Open dropdown for user-john
    const johnRow = page.locator('tr', { hasText: 'user-john' });
    await johnRow.locator('button').last().click();

    // Click Edit Attributes
    await page.locator('[role="menuitem"]').filter({ hasText: 'Edit Attributes' }).click();

    // Dialog should appear with current attributes
    await expect(page.locator('text=Edit Role Attributes')).toBeVisible();
    const input = page.locator('form input[placeholder*="engineering"]');
    await expect(input).toBeVisible();
    // Should contain current attributes
    await expect(input).toHaveValue('engineering, vpn-users');
  });

  test('should update identity attributes', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    // Open dropdown for user-john
    const johnRow = page.locator('tr', { hasText: 'user-john' });
    await johnRow.locator('button').last().click();
    await page.locator('[role="menuitem"]').filter({ hasText: 'Edit Attributes' }).click();

    // Modify attributes
    const input = page.locator('form input[placeholder*="engineering"]');
    await input.clear();
    await input.fill('engineering, finance, admin');

    // Submit
    await page.getByRole('button', { name: /save attributes/i }).click();
    await expect(page.locator('text=Attributes updated').first()).toBeVisible();
  });
});

test.describe('Ziti Identity Sync', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 2, identities_count: 5 }) });
    });

    await page.route('**/api/v1/access/ziti/identities', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          identities: [
            { id: '1', ziti_id: 'id-001', name: 'user-john', identity_type: 'User', user_id: 'user-1', enrolled: true, attributes: ['engineering'], created_at: '2024-01-01T00:00:00Z' },
          ],
        }),
      });
    });

    await page.route('**/api/v1/access/ziti/sync/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: 'idle',
          last_full_sync_at: '2024-01-20T10:00:00Z',
          last_auto_sync_at: '2024-01-20T12:30:00Z',
          users_synced: 5, users_failed: 0, groups_synced: 3,
          unsynced_users: 2, total_users: 7, total_identities: 5,
        }),
      });
    });

    await page.route('**/api/v1/access/ziti/sync/users', async (route) => {
      if (route.request().method() === 'POST') {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ users_synced: 2, users_failed: 0, groups_synced: 3 }) });
      }
    });

    await page.route('**/api/v1/access/ziti/sync/groups', async (route) => {
      if (route.request().method() === 'POST') {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ users_synced: 0, users_failed: 0, groups_synced: 5 }) });
      }
    });
  });

  test('should display sync status card on identities tab', async ({ page }) => {
    await page.goto('/ziti-network');
    await page.getByRole('tab', { name: /identities/i }).click();
    await expect(page.locator('text=Identity Sync')).toBeVisible();
    await expect(page.locator('text=5 identities / 7 users')).toBeVisible();
  });

  test('should show unsynced badge when users lack identities', async ({ page }) => {
    await page.goto('/ziti-network');
    await page.getByRole('tab', { name: /identities/i }).click();
    await expect(page.locator('text=2 unsynced')).toBeVisible();
  });

  test('should have Sync All Users button', async ({ page }) => {
    await page.goto('/ziti-network');
    await page.getByRole('tab', { name: /identities/i }).click();
    await expect(page.getByRole('button', { name: /sync all users/i })).toBeVisible();
  });

  test('should trigger sync all users and show success toast', async ({ page }) => {
    await page.goto('/ziti-network');
    await page.getByRole('tab', { name: /identities/i }).click();
    await page.getByRole('button', { name: /sync all users/i }).click();
    await expect(page.locator('text=Sync complete').first()).toBeVisible();
  });

  test('should trigger group sync and show success toast', async ({ page }) => {
    await page.goto('/ziti-network');
    await page.getByRole('tab', { name: /identities/i }).click();
    await page.getByRole('button', { name: /sync groups/i }).click();
    await expect(page.locator('text=Group sync complete').first()).toBeVisible();
  });
});

test.describe('Ziti Remote Access Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 5, identities_count: 10 }) });
    });

    await page.route('**/api/v1/access/ziti/browzer/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          enabled: true,
          configured: true,
          bootstrapper_url: 'https://browzer.example.com',
        }),
      });
    });

    await page.route('**/api/v1/access/guacamole/connections*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', route_id: 'route-1', protocol: 'ssh', hostname: 'server1.example.com', port: 22, created_at: '2024-01-01T00:00:00Z' },
          { id: '2', route_id: 'route-2', protocol: 'rdp', hostname: 'server2.example.com', port: 3389, created_at: '2024-01-05T00:00:00Z' },
        ]),
      });
    });
  });

  test('should display remote access tab content', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /remote access/i }).click();

    // Wait for content to load - look for BrowZer heading within the tab content
    await expect(page.locator('h3:has-text("BrowZer")').first()).toBeVisible();
  });

  test('should show BrowZer status', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /remote access/i }).click();

    await expect(page.locator('h3:has-text("BrowZer")').first()).toBeVisible();
  });

  test('should display external SSH connection for 10.0.0.10', async ({ page }) => {
    // Mock Guacamole connections with SSH to internal server
    await page.route('**/api/v1/access/guacamole/connections*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          connections: [
            {
              id: 'ssh-conn-1',
              route_id: 'route-ssh-internal',
              guacamole_connection_id: 'guac-ssh-001',
              protocol: 'ssh',
              hostname: '10.0.0.10',
              port: 22,
              parameters: { username: 'admin' },
              created_at: '2024-01-15T00:00:00Z',
              updated_at: '2024-01-15T00:00:00Z',
            },
          ],
        }),
      });
    });

    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /remote access/i }).click();

    // Verify SSH connection to internal server is displayed
    await expect(page.locator('text=10.0.0.10:22')).toBeVisible();
    await expect(page.locator('td:has-text("ssh")').first()).toBeVisible();
  });

  test('should display Guacamole SSH access URL for 10.0.0.10', async ({ page }) => {
    // Mock BrowZer status - base URL only
    await page.route('**/api/v1/access/ziti/browzer/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          enabled: true,
          configured: true,
          bootstrapper_url: 'https://browzer.localtest.me/',
          oidc_issuer: 'https://auth.localtest.me',
          oidc_client_id: 'browzer-client',
          external_jwt_signer_id: 'jwt-signer-001',
        }),
      });
    });

    // Mock Guacamole connections with SSH to internal server
    // Guacamole uses path: /guacamole/#/client/{encoded-connection-id}
    await page.route('**/api/v1/access/guacamole/connections*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          connections: [
            {
              id: 'ssh-conn-1',
              route_id: 'route-ssh-internal',
              guacamole_connection_id: 'c/internal-ssh-server',
              protocol: 'ssh',
              hostname: '10.0.0.10',
              port: 22,
              // Full Guacamole URL with path
              connect_url: 'https://browzer.localtest.me/guacamole/#/client/c/internal-ssh-server',
              parameters: { username: 'admin' },
              created_at: '2024-01-15T00:00:00Z',
              updated_at: '2024-01-15T00:00:00Z',
            },
          ],
        }),
      });
    });

    // Mock services list with SSH service
    await page.route('**/api/v1/access/ziti/services*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          services: [
            {
              id: 'ssh-svc-1',
              ziti_id: 'svc-ssh-001',
              name: 'internal-ssh-server',
              description: 'Internal SSH Server',
              protocol: 'tcp',
              host: '10.0.0.10',
              port: 22,
              enabled: true,
              created_at: '2024-01-15T00:00:00Z',
            },
          ],
        }),
      });
    });

    // Mock connect endpoint - returns Guacamole URL with /guacamole path
    await page.route('**/api/v1/access/guacamole/connections/*/connect', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          connect_url: 'https://browzer.localtest.me/guacamole/#/client/c/internal-ssh-server',
        }),
      });
    });

    await page.goto('/ziti-network');

    // Navigate to Remote Access tab
    await page.getByRole('tab', { name: /remote access/i }).click();

    // Verify BrowZer is enabled
    await expect(page.locator('h3:has-text("BrowZer")').first()).toBeVisible();
    await expect(page.locator('text=Enabled').first()).toBeVisible();

    // Verify SSH connection details
    await expect(page.locator('text=10.0.0.10').first()).toBeVisible();
    await expect(page.getByText(':22').first()).toBeVisible();

    // Verify Connect button exists for Guacamole access
    await expect(page.getByRole('button', { name: /connect/i })).toBeVisible();
  });

  test('should have Connect button for SSH external access', async ({ page }) => {
    await page.route('**/api/v1/access/guacamole/connections*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          connections: [
            {
              id: 'ssh-conn-1',
              route_id: 'route-ssh-internal',
              guacamole_connection_id: 'guac-ssh-001',
              protocol: 'ssh',
              hostname: '10.0.0.10',
              port: 22,
              parameters: {},
              created_at: '2024-01-15T00:00:00Z',
              updated_at: '2024-01-15T00:00:00Z',
            },
          ],
        }),
      });
    });

    // Mock connect endpoint
    await page.route('**/api/v1/access/guacamole/connections/*/connect', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          connect_url: 'https://guacamole.example.com/#/client/c/guac-ssh-001',
        }),
      });
    });

    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /remote access/i }).click();

    // Verify Connect button is available
    await expect(page.getByRole('button', { name: /connect/i })).toBeVisible();
  });

  // ─── New Quick-Win Improvement Tests ────────────────────────────────────────

  test.describe('Service Test Connection', () => {
    test.beforeEach(async ({ page }) => {
      await page.route('**/api/v1/access/ziti/services', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            services: [
              { id: 'svc-1', ziti_id: 'ziti-svc-001', name: 'internal-app', description: 'Internal app', protocol: 'tcp', host: 'internal-app', port: 8080, enabled: true, created_at: '2024-01-01T00:00:00Z' },
            ],
          }),
        });
      });

      await page.route('**/api/v1/access/ziti/services/svc-1/test', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            success: true,
            service_name: 'internal-app',
            tests: {
              ziti_lookup: { success: true, latency_ms: 15 },
              ziti_dial: { success: true, latency_ms: 42 },
            },
            tested_at: new Date().toISOString(),
          }),
        });
      });
    });

    test('should have Test Connection option in service dropdown', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /services/i }).click();
      // Open the "..." dropdown menu for the service row (last button in row)
      const row = page.locator('table tbody tr').first();
      await row.locator('button').last().click();
      await expect(page.getByRole('menuitem', { name: /test connection/i })).toBeVisible();
    });
  });

  test.describe('Unsynced Users Expandable List', () => {
    test.beforeEach(async ({ page }) => {
      await page.route('**/api/v1/access/ziti/sync/status', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            status: 'idle', unsynced_users: 2, total_users: 7, total_identities: 5,
            last_auto_sync_at: '2024-01-20T12:30:00Z',
          }),
        });
      });

      await page.route('**/api/v1/access/ziti/sync/unsynced', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            { id: 'user-1', username: 'jdoe', email: 'jdoe@example.com', first_name: 'John', last_name: 'Doe' },
            { id: 'user-2', username: 'asmith', email: 'asmith@example.com', first_name: 'Alice', last_name: 'Smith' },
          ]),
        });
      });

      await page.route('**/api/v1/access/ziti/identities', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ identities: [] }),
        });
      });

      await page.route('**/api/v1/access/ziti/sync/users/*', async (route) => {
        if (route.request().method() === 'POST') {
          await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ user_id: 'user-1', ziti_id: 'z1', created: true, attributes: [] }) });
        }
      });
    });

    test('should expand unsynced list when clicking the badge', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /identities/i }).click();
      // Click the unsynced badge
      await page.locator('text=2 unsynced').click();
      // Should show the user list
      await expect(page.locator('text=jdoe')).toBeVisible();
      await expect(page.locator('text=asmith')).toBeVisible();
    });

    test('should have individual Sync button for each unsynced user', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /identities/i }).click();
      await page.locator('text=2 unsynced').click();
      // Each user should have a Sync button
      const syncButtons = page.locator('text=Users without Ziti identities').locator('..').getByRole('button', { name: /^sync$/i });
      await expect(syncButtons).toHaveCount(2);
    });
  });

  test.describe('Edge Router Policies', () => {
    test.beforeEach(async ({ page }) => {
      await page.route('**/api/v1/access/ziti/edge-router-policies', async (route) => {
        if (route.request().method() === 'GET') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify([
              { id: 'erp-1', name: 'allEdgeRouters', edgeRouterRoles: ['#all'], identityRoles: ['#all'] },
              { id: 'erp-2', name: 'engineering-routers', edgeRouterRoles: ['#datacenter-us'], identityRoles: ['#engineering'] },
            ]),
          });
        }
      });

      await page.route('**/api/v1/access/ziti/fabric/service-policies', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });

      await page.route('**/api/v1/access/ziti/posture/checks', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });

      await page.route('**/api/v1/access/ziti/posture/summary', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ total_checks: 0, enabled_checks: 0, disabled_checks: 0, by_type: {}, by_severity: {} }) });
      });

      await page.route('**/api/v1/access/ziti/certificates', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });

      await page.route('**/api/v1/access/ziti/certificates/expiry-alerts', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ alerts: [] }) });
      });

      await page.route('**/api/v1/access/ziti/policy-sync', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });

      await page.route('**/api/v1/governance/policies', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });
    });

    test('should display Edge Router Policies section on Security tab', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      await expect(page.locator('text=Edge Router Policies')).toBeVisible();
    });

    test('should expand and show edge router policies', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      // Click to expand the section
      await page.locator('button:has-text("Edge Router Policies")').click();
      await expect(page.locator('text=allEdgeRouters')).toBeVisible();
      await expect(page.locator('text=engineering-routers')).toBeVisible();
    });

    test('should have Add Policy button in edge router policies', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      await page.locator('button:has-text("Edge Router Policies")').click();
      await expect(page.getByRole('button', { name: /add policy/i }).first()).toBeVisible();
    });
  });

  test.describe('Policy Notation Readability', () => {
    test.beforeEach(async ({ page }) => {
      await page.route('**/api/v1/access/ziti/fabric/service-policies', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            { id: 'sp-1', name: 'allow-engineering', type: 'Dial', serviceRoles: ['#internal-apps', '#gitlab'], identityRoles: ['#engineering'] },
          ]),
        });
      });

      await page.route('**/api/v1/access/ziti/edge-router-policies', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });

      await page.route('**/api/v1/access/ziti/posture/checks', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });

      await page.route('**/api/v1/access/ziti/posture/summary', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ total_checks: 0, enabled_checks: 0, disabled_checks: 0 }) });
      });

      await page.route('**/api/v1/access/ziti/certificates', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });

      await page.route('**/api/v1/access/ziti/certificates/expiry-alerts', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ alerts: [] }) });
      });

      await page.route('**/api/v1/access/ziti/policy-sync', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });

      await page.route('**/api/v1/governance/policies', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });
    });

    test('should show color-coded role badges in service policies', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      // Service roles should show with readable labels
      await expect(page.locator('text=internal-apps').first()).toBeVisible();
      await expect(page.locator('text=engineering').first()).toBeVisible();
    });
  });

  test.describe('Governance Policy Sync Enhancement', () => {
    test.beforeEach(async ({ page }) => {
      await page.route('**/api/v1/access/ziti/fabric/service-policies', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });

      await page.route('**/api/v1/access/ziti/edge-router-policies', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });

      await page.route('**/api/v1/access/ziti/posture/checks', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });

      await page.route('**/api/v1/access/ziti/posture/summary', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ total_checks: 0, enabled_checks: 0, disabled_checks: 0 }) });
      });

      await page.route('**/api/v1/access/ziti/certificates', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });

      await page.route('**/api/v1/access/ziti/certificates/expiry-alerts', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ alerts: [] }) });
      });

      await page.route('**/api/v1/access/ziti/policy-sync', async (route) => {
        if (route.request().method() === 'GET') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify([
              { id: 'ps-1', governance_policy_id: 'gov-1', ziti_policy_id: 'ziti-pol-1', sync_status: 'synced', last_synced_at: '2024-01-20T10:00:00Z', error_message: '' },
            ]),
          });
        }
      });

      await page.route('**/api/v1/governance/policies', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            { id: 'gov-1', name: 'Vendor Access Policy', description: 'Controls vendor VPN access' },
            { id: 'gov-2', name: 'Engineering Policy', description: 'Engineering team access' },
          ]),
        });
      });
    });

    test('should show Governance → Ziti Sync section with linked policies', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      // Expand the sync section
      await page.locator('button:has-text("Governance")').click();
      await expect(page.locator('text=Vendor Access Policy')).toBeVisible();
    });

    test('should have Link Policy and Sync All buttons', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      await page.locator('button:has-text("Governance")').click();
      await expect(page.getByRole('button', { name: /link policy/i })).toBeVisible();
      await expect(page.getByRole('button', { name: /sync all/i })).toBeVisible();
    });

    test('should sync governance policy with auto-fetch enabled', async ({ page }) => {
      let syncPayload: unknown = null;
      await page.route('**/api/v1/access/ziti/policy-sync', async (route) => {
        if (route.request().method() === 'POST') {
          syncPayload = route.request().postDataJSON();
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ message: 'policy synced successfully', auto_fetched: true }),
          });
        } else {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify([]),
          });
        }
      });

      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      await page.locator('button:has-text("Governance")').click();
      await page.getByRole('button', { name: /link policy/i }).click();

      // Select a governance policy
      const select = page.locator('form select').first();
      await select.selectOption('gov-1');

      // Auto-detect should be on by default (Switch component)
      await expect(page.locator('text=Auto-detect policy rules')).toBeVisible();

      // Submit the sync
      await page.getByRole('button', { name: /link policy/i }).last().click();

      // Verify auto_fetch was sent in the request
      expect(syncPayload).toMatchObject({ governance_policy_id: 'gov-1', auto_fetch: true });
      await expect(page.locator('text=Policy sync created').first()).toBeVisible();
    });
  });

  // ─── F14: Active Sessions ──────────────────────────────────────────────────

  test.describe('Active Sessions', () => {
    test.beforeEach(async ({ page }) => {
      await page.route('**/api/v1/access/ziti/sessions', async (route) => {
        if (route.request().method() === 'GET') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify([
              { id: 'sess-1', type: 'Dial', identity: { id: 'id-1', name: 'alice' }, service: { id: 'svc-1', name: 'internal-app' }, createdAt: '2024-01-01T10:00:00Z' },
              { id: 'sess-2', type: 'Bind', identity: { id: 'id-2', name: 'router-host' }, service: { id: 'svc-2', name: 'ssh-service' }, createdAt: '2024-01-01T09:00:00Z' },
            ]),
          });
        } else {
          await route.fulfill({ status: 200, contentType: 'application/json', body: '{"message":"session terminated"}' });
        }
      });
    });

    test('should display Active Sessions section on Security tab', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      await expect(page.getByRole('button', { name: 'Active Sessions' })).toBeVisible();
    });

    test('should show session entries with identity and service names', async ({ page }) => {
      await page.goto('/ziti-network');
      // Click Security tab and wait for sessions API response (query fires on SecurityTab mount)
      await Promise.all([
        page.waitForResponse(resp => resp.url().includes('/ziti/sessions') && resp.status() === 200),
        page.getByRole('tab', { name: /security/i }).click(),
      ]);
      await expect(page.getByRole('cell', { name: 'alice' })).toBeVisible();
      await expect(page.getByRole('cell', { name: 'internal-app' })).toBeVisible();
      // Verify session types exist in the Active Sessions table (use .first() since Dial/Bind also appear in Service Policies)
      await expect(page.getByRole('cell', { name: 'Dial' }).first()).toBeVisible();
      await expect(page.getByRole('cell', { name: 'Bind' }).first()).toBeVisible();
    });

    test('should batch terminate all sessions for an identity', async ({ page }) => {
      // Need 2+ unique identities to show batch terminate buttons
      await page.route('**/api/v1/access/ziti/sessions', async (route) => {
        if (route.request().method() === 'GET') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify([
              { id: 'sess-1', type: 'Dial', identity: { id: 'id-1', name: 'alice' }, service: { id: 'svc-1', name: 'internal-app' }, createdAt: '2024-01-01T10:00:00Z' },
              { id: 'sess-2', type: 'Dial', identity: { id: 'id-2', name: 'bob' }, service: { id: 'svc-2', name: 'ssh-service' }, createdAt: '2024-01-01T09:00:00Z' },
            ]),
          });
        } else {
          await route.fallback();
        }
      });

      await page.route('**/api/v1/access/ziti/sessions/batch-terminate', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'sessions terminated', sessions_terminated: 1 }),
        });
      });

      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();

      // Click the batch terminate button and wait for the POST request deterministically
      const [request] = await Promise.all([
        page.waitForRequest(req => req.url().includes('batch-terminate') && req.method() === 'POST'),
        page.getByRole('button', { name: /Terminate All: alice/i }).click(),
      ]);

      // Verify the POST was sent with the correct identity_id
      expect(request.postDataJSON()).toEqual({ identity_id: 'id-1' });
      await expect(page.locator('text=All sessions terminated').first()).toBeVisible();
    });
  });

  // ─── Posture Identity Viewer ────────────────────────────────────────────────

  test.describe('Posture Identity Viewer', () => {
    test.beforeEach(async ({ page }) => {
      await page.route('**/api/v1/access/ziti/posture/checks*', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            { id: 'chk-1', name: 'OS Check', check_type: 'OS', enabled: true, severity: 'high', created_at: '2024-01-01T00:00:00Z' },
          ]),
        });
      });

      await page.route('**/api/v1/access/ziti/posture/summary', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ total_checks: 1, enabled_checks: 1 }) });
      });

      await page.route('**/api/v1/access/ziti/certificates*', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
      });

      await page.route('**/api/v1/access/ziti/posture/identities/id-test-001', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            overall_passed: true,
            results: [
              { id: 'r-1', identity_id: 'id-test-001', check_id: 'chk-1', passed: true, details: { os: 'Windows' }, checked_at: '2024-01-20T10:00:00Z', expires_at: '2024-01-20T11:00:00Z' },
            ],
          }),
        });
      });

      await page.route('**/api/v1/access/ziti/posture/identities/id-test-001/evaluate', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ passed: true, results: [] }),
        });
      });
    });

    test('should look up posture status for an identity and show results', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();

      // Find the identity posture lookup input and enter an ID
      await page.getByPlaceholder('Enter identity ID...').fill('id-test-001');
      await page.getByRole('button', { name: /lookup/i }).click();

      // Should show passed badge
      await expect(page.locator('text=Passed').first()).toBeVisible();
    });

    test('should trigger posture evaluation with Evaluate Now button', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();

      await page.getByPlaceholder('Enter identity ID...').fill('id-test-001');
      await page.getByRole('button', { name: /lookup/i }).click();

      // Wait for results to load, then click Evaluate Now
      await expect(page.locator('text=Passed').first()).toBeVisible();
      await page.getByRole('button', { name: /evaluate now/i }).click();

      await expect(page.locator('text=Posture evaluation triggered').first()).toBeVisible();
    });
  });

  // ─── F11: Configurations ───────────────────────────────────────────────────

  test.describe('Configurations Section', () => {
    test.beforeEach(async ({ page }) => {
      await page.route('**/api/v1/access/ziti/configs', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            { id: 'cfg-1', name: 'openidx-host-app', configTypeId: 'ct-1', configType: { id: 'ct-1', name: 'host.v1' }, data: { protocol: 'tcp', address: 'localhost', port: 8080 } },
          ]),
        });
      });
      await page.route('**/api/v1/access/ziti/config-types', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            { id: 'ct-1', name: 'host.v1' },
            { id: 'ct-2', name: 'intercept.v1' },
          ]),
        });
      });
    });

    test('should display Configurations section on Security tab', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      await page.locator('button:has-text("Configurations")').click();
      await expect(page.getByText('openidx-host-app')).toBeVisible();
      await expect(page.getByText('host.v1', { exact: true })).toBeVisible();
    });

    test('should have Add Config button', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      await page.locator('button:has-text("Configurations")').click();
      await expect(page.getByRole('button', { name: /add config/i })).toBeVisible();
    });
  });

  // ─── F12: Auth Policies & JWT Signers ──────────────────────────────────────

  test.describe('Auth Policies & JWT Signers', () => {
    test.beforeEach(async ({ page }) => {
      await page.route('**/api/v1/access/ziti/auth-policies', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            { id: 'ap-1', name: 'default', primary: { cert: { allowed: true }, updb: { allowed: true }, extJwt: { allowed: false } }, secondary: { requireTotp: false } },
            { id: 'ap-2', name: 'openidx-browzer-auth', primary: { cert: { allowed: false }, updb: { allowed: false }, extJwt: { allowed: true } }, secondary: { requireTotp: false } },
          ]),
        });
      });
      await page.route('**/api/v1/access/ziti/jwt-signers', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            { id: 'js-1', name: 'openidx-oauth-browzer', issuer: 'https://auth.example.com', audience: 'admin-console', jwksEndpoint: 'https://auth.example.com/jwks', claimsProperty: 'sub', useExternalId: true, enabled: true },
          ]),
        });
      });
    });

    test('should display Auth Policies section on Security tab', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      await page.locator('button:has-text("Auth Policies")').click();
      await expect(page.getByRole('heading', { name: 'Auth Policies' })).toBeVisible();
      await expect(page.getByRole('heading', { name: 'JWT Signers' })).toBeVisible();
    });

    test('should show auth policy entries with auth method badges', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      await page.locator('button:has-text("Auth Policies")').click();
      await expect(page.getByText('Cert', { exact: true })).toBeVisible();
      await expect(page.getByText('UPDB', { exact: true })).toBeVisible();
    });

    test('should show JWT signer entries', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      await page.locator('button:has-text("Auth Policies")').click();
      await expect(page.getByText('openidx-oauth-browzer')).toBeVisible();
    });
  });

  // ─── F13: Terminators ──────────────────────────────────────────────────────

  test.describe('Terminators Section', () => {
    test.beforeEach(async ({ page }) => {
      await page.route('**/api/v1/access/ziti/terminators', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            { id: 'term-1', serviceId: 'svc-1', service: { id: 'svc-1', name: 'internal-app' }, routerId: 'r-1', router: { id: 'r-1', name: 'edge-router-1' }, binding: 'edge', address: 'tcp:localhost:8080', cost: 0, precedence: 'default', createdAt: '2024-01-01T00:00:00Z' },
          ]),
        });
      });
    });

    test('should display Terminators section on Security tab', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      await page.locator('button:has-text("Terminators")').click();
      // Use cell locators to match within the Terminators table specifically
      await expect(page.getByRole('cell', { name: 'internal-app' })).toBeVisible();
      await expect(page.getByRole('cell', { name: 'edge-router-1' })).toBeVisible();
    });

    test('should show terminator details', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /security/i }).click();
      await page.locator('button:has-text("Terminators")').click();
      await expect(page.getByText('tcp:localhost:8080')).toBeVisible();
      await expect(page.getByText('edge', { exact: true })).toBeVisible();
    });
  });

  // ─── F15: Published App Services ───────────────────────────────────────────

  test.describe('Published App Services', () => {
    test.beforeEach(async ({ page }) => {
      await page.route('**/api/v1/access/ziti/services', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ services: [
            { id: '1', ziti_id: 'svc-001', name: 'web-service', protocol: 'tcp', host: '10.0.0.1', port: 443, enabled: true, created_at: '2024-01-01T00:00:00Z' },
          ] }),
        });
      });
      await page.route('**/api/v1/access/apps', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ apps: [
            { id: 'app-1', name: 'My Web App', target_url: 'http://internal-app:8080', total_paths_published: 3, status: 'published' },
          ], total: 1 }),
        });
      });
      await page.route('**/api/v1/access/apps/app-1/ziti-services', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ services: [
            { id: 's1', ziti_id: 'z1', name: 'openidx-my-web-app-api', protocol: 'tcp', host: 'internal-app', port: 8080, enabled: true, linked_path: '/api', classification: 'protected', route_name: 'my-web-app-api' },
          ], app_name: 'My Web App' }),
        });
      });
    });

    test('should show Published App Services section in Services tab', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /services/i }).click();
      await expect(page.getByText('Published App Services')).toBeVisible();
      await expect(page.getByText('My Web App')).toBeVisible();
    });

    test('should expand app to show linked Ziti services', async ({ page }) => {
      await page.goto('/ziti-network');
      await page.getByRole('tab', { name: /services/i }).click();
      await page.locator('button:has-text("My Web App")').click();
      await expect(page.getByText('openidx-my-web-app-api')).toBeVisible();
      await expect(page.getByText('/api')).toBeVisible();
      await expect(page.getByText('protected')).toBeVisible();
    });
  });
});
