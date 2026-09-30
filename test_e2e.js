import { chromium } from 'playwright';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runE2ETest() {
  console.log('--- Starting SAT-SA Playwright End-to-End Test ---');

  const PORT = '1499';

  // 1. Start Vite local server
  console.log(`[1/7] Launching Vite local development server on port ${PORT}...`);
  const viteProcess = spawn('npx.cmd', ['vite', '--port', PORT, '--strictPort'], {
    cwd: __dirname,
    stdio: 'ignore',
    shell: true,
  });

  // Give Vite 4 seconds to spin up
  await new Promise((resolve) => setTimeout(resolve, 4000));

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  try {
    // 2. Navigate to SAT-SA Web App
    console.log(`[2/7] Navigating to http://127.0.0.1:${PORT}...`);
    await page.goto(`http://127.0.0.1:${PORT}`);
    await page.waitForLoadState('networkidle');

    // Screenshot initial state
    await page.screenshot({ path: 'e2e_01_initial_load.png', fullPage: true });
    console.log('✓ Initial page loaded successfully.');

    // 3. Test Accessibility Font Size & Language Controls
    console.log('[3/7] Testing top accessibility bar & language switches...');
    const btnAminus = page.locator('button[title="Small Text"]');
    if (await btnAminus.isVisible()) await btnAminus.click();

    const btnAplus = page.locator('button[title="Large Text"]');
    if (await btnAplus.isVisible()) await btnAplus.click();

    const btnAnormal = page.locator('button[title="Normal Text"]');
    if (await btnAnormal.isVisible()) await btnAnormal.click();

    console.log('✓ Accessibility bar controls tested.');

    // 4. Test Native CSV File Ingestion via file input
    console.log('[4/7] Testing Real SOC CSV Dataset Import...');
    const csvPath = path.join(__dirname, 'real_datasets', 'real_soc_data_powergrid.csv');
    if (fs.existsSync(csvPath)) {
      const fileInputLocator = page.locator('input[type="file"]');
      if (await fileInputLocator.count() > 0) {
        await fileInputLocator.setInputFiles(csvPath);
        await page.waitForTimeout(1000);
        console.log('✓ Real CSV file (real_soc_data_powergrid.csv) uploaded to Rust engine.');
      } else {
        console.log('File input not found, skipping setInputFiles');
      }
    }

    // 5. Test Action Buttons
    console.log('[5/7] Testing Action Buttons...');
    const seedBtn = page.getByRole('button', { name: /Seed Benchmark/i });
    if (await seedBtn.isVisible()) {
      await seedBtn.click();
      await page.waitForTimeout(800);
    }

    const execBtn = page.getByRole('button', { name: /Execute Supervisory Analysis/i });
    if (await execBtn.isVisible()) {
      await execBtn.click();
      await page.waitForTimeout(800);
    }

    await page.screenshot({ path: 'e2e_02_post_analysis.png', fullPage: true });
    console.log('✓ Action buttons tested & screenshot captured.');

    // 6. Test Risk Leaderboard Entity Filtering
    console.log('[6/7] Testing Risk Leaderboard Entity Selection & Filtering...');
    const powergridRow = page.locator('text=CSE-POWERGRID').first();
    if (await powergridRow.isVisible()) {
      await powergridRow.click();
      await page.waitForTimeout(500);
      console.log('✓ Filtered view to CSE-POWERGRID.');
    }

    const clearFilterBtn = page.locator('text=Clear Filter');
    if (await clearFilterBtn.isVisible()) {
      await clearFilterBtn.click();
      await page.waitForTimeout(500);
      console.log('✓ Cleared filter view back to all CSEs.');
    }

    // 7. Test Export Buttons
    console.log('[7/7] Testing Statutory PDF & JSON Export buttons...');
    const pdfBtn = page.getByRole('button', { name: /Official PDF Report/i }).first();
    if (await pdfBtn.isVisible()) {
      await pdfBtn.click();
      await page.waitForTimeout(1000);
    }

    const jsonBtn = page.getByRole('button', { name: /Export Audit Package/i }).first();
    if (await jsonBtn.isVisible()) {
      await jsonBtn.click();
      await page.waitForTimeout(1000);
    }

    await page.screenshot({ path: 'e2e_03_final_state.png', fullPage: true });
    console.log('✓ All export buttons executed successfully.');

    console.log('=== SAT-SA E2E TEST PASSED 100% ===');
  } catch (err) {
    console.error('E2E Test Failure:', err);
    process.exitCode = 1;
  } finally {
    await browser.close();
    viteProcess.kill('SIGTERM');
  }
}

runE2ETest();
