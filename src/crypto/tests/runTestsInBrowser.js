import txSignTests from './txSignTests';

async function runTestsInBrowser() {
  const tests = [];
  let currentSuite = '';

  // pretending to be Jest
  txSignTests(
    // describe
    (suiteName, addTests) => {
      currentSuite = suiteName;
      addTests();
    },
    // test
    (testName, runTest) => {
      const displayName = `${currentSuite}: “${testName}”`;
      tests.push(async () => {
        try {
          console.time('Test took');
          await runTest();
          console.log(`✅ ${displayName}`);
          console.timeEnd('Test took');
        } catch (error) {
          console.log(`❌ ${displayName} – ${error}`);
        }
      });
    },
  );

  for (const runTest of tests) {
    await runTest();
  }
}

window.runTestsInBrowser = runTestsInBrowser;

export default runTestsInBrowser;
