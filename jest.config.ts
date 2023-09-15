import { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  logHeapUsage: true,
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: '.',
  roots: ['<rootDir>/src'],
  testRegex: '.*\\.spec\\.ts$',
  transform: {
    '^.+\\.(t|j)s$': 'ts-jest',
  },
  collectCoverageFrom: ['**/*.(t|j)s'],
  coverageDirectory: './coverage',
  globals: {
    /**
     * Because @meeco/sdk expects it...
     */
    FormData: null,
  },
  coveragePathIgnorePatterns: ['/node_modules/', '/src/test-utils/'],
  moduleNameMapper: {
    '^@sd-jwt/test-utils(.*)$': '<rootDir>/src/test-utils/$1',
  },
};

export default config;
