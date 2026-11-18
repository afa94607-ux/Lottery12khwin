import express, { Request, Response, NextFunction } from 'express';
import http from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.resolve(__dirname, 'data');
const PERSISTENCE_FILE = path.resolve(DATA_DIR, 'lottery_server_state.json');

try {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
} catch (e) {
  console.warn('Failed to ensure data dir exists', e);
}

// ========================================================
// CRYPTOGRAPHIC PASSWORD HASHING & SESSION UTILITIES
// ========================================================

function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derivedKey}`;
}

function verifyPassword(password: string, storedHash: string): boolean {
  try {
    const [salt, key] = storedHash.split(':');
    if (!salt || !key) return false;
    const keyBuffer = Buffer.from(key, 'hex');
    const derivedBuffer = crypto.scryptSync(password, salt, 64);
    if (keyBuffer.length !== derivedBuffer.length) return false;
    return crypto.timingSafeEqual(keyBuffer, derivedBuffer);
  } catch {
    return false;
  }
}

function generateSecureToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('hex');
}

function formatNowTimestamp(): string {
  const now = new Date();
  const yyyy = now.getFullYear();
  const mm = String(now.getMonth() + 1).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  const hh = String(now.getHours()).padStart(2, '0');
  const min = String(now.getMinutes()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd} ${hh}:${min}`;
}

function formatShortTime(): string {
  const now = new Date();
  return `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
}

function parseCookies(cookieHeader?: string): Record<string, string> {
  const list: Record<string, string> = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach((cookie) => {
    const parts = cookie.split('=');
    const key = parts.shift()?.trim();
    if (key) {
      list[key] = decodeURIComponent(parts.join('=').trim());
    }
  });
  return list;
}

// ========================================================
// DATA TYPES
// ========================================================

type ColorGroup = 'red' | 'green' | 'blue';
type SizeGroup = 'small' | 'big';
type ParityGroup = 'odd' | 'even';
type BetCategory =
  | 'small'
  | 'big'
  | 'odd'
  | 'even'
  | 'color_red'
  | 'color_green'
  | 'color_blue'
  | `animal_${number}`;

interface AnimalData {
  number: number;
  khmerName: string;
  animalEn: string;
  color: ColorGroup;
  size: SizeGroup;
  parity: ParityGroup;
  odds: number;
}

const ANIMALS_DATA: Record<number, AnimalData> = {
  1: { number: 1, khmerName: 'ជូត', animalEn: 'Rat', color: 'red', size: 'small', parity: 'odd', odds: 11 },
  2: { number: 2, khmerName: 'ឆ្លូវ', animalEn: 'Ox', color: 'green', size: 'small', parity: 'even', odds: 11 },
  3: { number: 3, khmerName: 'ខាល', animalEn: 'Tiger', color: 'blue', size: 'small', parity: 'odd', odds: 11 },
  4: { number: 4, khmerName: 'ថោះ', animalEn: 'Rabbit', color: 'red', size: 'small', parity: 'even', odds: 11 },
  5: { number: 5, khmerName: 'រោង', animalEn: 'Dragon', color: 'green', size: 'small', parity: 'odd', odds: 11 },
  6: { number: 6, khmerName: 'ម្សាញ់', animalEn: 'Snake', color: 'blue', size: 'small', parity: 'even', odds: 11 },
  7: { number: 7, khmerName: 'មមី', animalEn: 'Horse', color: 'red', size: 'big', parity: 'odd', odds: 11 },
  8: { number: 8, khmerName: 'មមែ', animalEn: 'Goat', color: 'green', size: 'big', parity: 'even', odds: 11 },
  9: { number: 9, khmerName: 'វក', animalEn: 'Monkey', color: 'blue', size: 'big', parity: 'odd', odds: 11 },
  10: { number: 10, khmerName: 'រកា', animalEn: 'Rooster', color: 'red', size: 'big', parity: 'even', odds: 11 },
  11: { number: 11, khmerName: 'ច', animalEn: 'Dog', color: 'green', size: 'big', parity: 'odd', odds: 11 },
  12: { number: 12, khmerName: 'កុរ', animalEn: 'Pig', color: 'blue', size: 'big', parity: 'even', odds: 11 },
};

interface DrawResult {
  roundId: string;
  roundIndex: number;
  time: string;
  number: number;
  animal: string;
  color: ColorGroup;
  size: SizeGroup;
  parity: ParityGroup;
  timestamp: number;
}

interface BetHistoryRecord {
  id: string;
  roundId: string;
  time: string;
  playerId?: string;
  username?: string;
  bets: {
    type: BetCategory;
    label: string;
    amount: number;
    odds: number;
    potentialWin?: number;
    won: boolean;
    payout: number;
  }[];
  totalStake: number;
  totalPotentialPayout: number;
  totalPayout: number;
  netProfit: number;
  resultNumber?: number;
  status: 'won' | 'lost' | 'pending';
}

interface TransactionRecord {
  id: string;
  playerId?: string;
  userName: string;
  userPhone: string;
  type: 'deposit' | 'withdrawal' | 'adjustment';
  amount: number;
  method: 'ABA Bank' | 'Wing' | 'ACLEDA' | 'TrueMoney' | 'Cash' | 'Manual';
  status: 'pending' | 'approved' | 'rejected';
  timestamp: number;
  timeString: string;
  note?: string;
}

type AccountStatus = 'active' | 'disabled';
type AdminRole = 'super_admin' | 'operations_admin' | 'finance_auditor';

interface StoredPlayerAccount {
  id: string;
  username: string;
  displayName: string;
  phone: string;
  passwordHash: string;
  status: AccountStatus;
  balance: number;
  betsCount7d: number;
  createdAt: string;
  lastLogin: string | null;
  sessionVersion: number;
}

interface StoredAdminAccount {
  id: string;
  username: string;
  displayName: string;
  role: AdminRole;
  permissions: string[];
  passwordHash: string;
  status: AccountStatus;
  createdAt: string;
  lastLogin: string | null;
  sessionVersion: number;
}

interface SessionRecord {
  token: string;
  csrfToken: string;
  accountId: string;
  username: string;
  role: 'player' | AdminRole;
  sessionVersion: number;
  createdAt: number;
  expiresAt: number;
  ip: string;
  userAgent: string;
}

interface AuditLogEntry {
  id: string;
  timestamp: number;
  timeString: string;
  actorId: string;
  actorUsername: string;
  actorRole: string;
  action: string;
  targetId?: string;
  targetName?: string;
  details: string;
  ip?: string;
}

interface PlatformSettings {
  roundDurationSeconds: number;
  bettingLockoutSeconds: number;
  isRoundPaused: boolean;
  minBetRiel: number;
  maxBetRiel: number;
  animalOdds: number;
  colorOdds: number;
  sizeParityOdds: number;
  maintenanceMode: boolean;
  sessionTimeoutMinutes: number;
}

// Initial History
const INITIAL_HISTORY: DrawResult[] = [
  { roundId: '2004#283', roundIndex: 283, time: '16:19', number: 1, animal: 'ជូត', color: 'red', size: 'small', parity: 'odd', timestamp: Date.now() - 60000 },
  { roundId: '2004#282', roundIndex: 282, time: '16:15', number: 9, animal: 'វក', color: 'blue', size: 'big', parity: 'odd', timestamp: Date.now() - 120000 },
  { roundId: '2004#281', roundIndex: 281, time: '16:12', number: 8, animal: 'មមែ', color: 'green', size: 'big', parity: 'even', timestamp: Date.now() - 180000 },
  { roundId: '2004#280', roundIndex: 280, time: '16:08', number: 10, animal: 'រកា', color: 'red', size: 'big', parity: 'even', timestamp: Date.now() - 240000 },
  { roundId: '2004#279', roundIndex: 279, time: '16:05', number: 11, animal: 'ច', color: 'green', size: 'big', parity: 'odd', timestamp: Date.now() - 300000 },
  { roundId: '2004#278', roundIndex: 278, time: '16:01', number: 12, animal: 'កុរ', color: 'blue', size: 'big', parity: 'even', timestamp: Date.now() - 360000 },
  { roundId: '2004#277', roundIndex: 277, time: '15:58', number: 9, animal: 'វក', color: 'blue', size: 'big', parity: 'odd', timestamp: Date.now() - 420000 },
  { roundId: '2004#276', roundIndex: 276, time: '15:54', number: 10, animal: 'រកា', color: 'red', size: 'big', parity: 'even', timestamp: Date.now() - 480000 },
  { roundId: '2004#275', roundIndex: 275, time: '15:50', number: 8, animal: 'មមែ', color: 'green', size: 'big', parity: 'even', timestamp: Date.now() - 540000 },
  { roundId: '2004#274', roundIndex: 274, time: '15:47', number: 6, animal: 'ម្សាញ់', color: 'blue', size: 'small', parity: 'even', timestamp: Date.now() - 600000 },
  { roundId: '2004#273', roundIndex: 273, time: '15:43', number: 2, animal: 'ឆ្លូវ', color: 'green', size: 'small', parity: 'even', timestamp: Date.now() - 660000 },
  { roundId: '2004#272', roundIndex: 272, time: '15:40', number: 12, animal: 'កុរ', color: 'blue', size: 'big', parity: 'even', timestamp: Date.now() - 720000 },
  { roundId: '2004#271', roundIndex: 271, time: '15:36', number: 6, animal: 'ម្សាញ់', color: 'blue', size: 'small', parity: 'even', timestamp: Date.now() - 780000 },
  { roundId: '2004#270', roundIndex: 270, time: '15:32', number: 8, animal: 'មមែ', color: 'green', size: 'big', parity: 'even', timestamp: Date.now() - 840000 },
  { roundId: '2004#269', roundIndex: 269, time: '15:28', number: 11, animal: 'ច', color: 'green', size: 'big', parity: 'odd', timestamp: Date.now() - 900000 },
  { roundId: '2004#268', roundIndex: 268, time: '15:25', number: 6, animal: 'ម្សាញ់', color: 'blue', size: 'small', parity: 'even', timestamp: Date.now() - 960000 },
  { roundId: '2004#267', roundIndex: 267, time: '15:21', number: 7, animal: 'មមី', color: 'red', size: 'big', parity: 'odd', timestamp: Date.now() - 1020000 },
  { roundId: '2004#266', roundIndex: 266, time: '15:18', number: 5, animal: 'រោង', color: 'green', size: 'small', parity: 'odd', timestamp: Date.now() - 1080000 },
  { roundId: '2004#265', roundIndex: 265, time: '15:14', number: 5, animal: 'រោង', color: 'green', size: 'small', parity: 'odd', timestamp: Date.now() - 1140000 },
  { roundId: '2004#264', roundIndex: 264, time: '15:10', number: 1, animal: 'ជូត', color: 'red', size: 'small', parity: 'odd', timestamp: Date.now() - 1200000 },
  { roundId: '2004#263', roundIndex: 263, time: '15:06', number: 6, animal: 'ម្សាញ់', color: 'blue', size: 'small', parity: 'even', timestamp: Date.now() - 1260000 },
  { roundId: '2004#262', roundIndex: 262, time: '15:02', number: 10, animal: 'រកា', color: 'red', size: 'big', parity: 'even', timestamp: Date.now() - 1320000 },
  { roundId: '2004#261', roundIndex: 261, time: '14:58', number: 7, animal: 'មមី', color: 'red', size: 'big', parity: 'odd', timestamp: Date.now() - 1380000 },
  { roundId: '2004#260', roundIndex: 260, time: '14:54', number: 1, animal: 'ជូត', color: 'red', size: 'small', parity: 'odd', timestamp: Date.now() - 1440000 },
  { roundId: '2004#259', roundIndex: 259, time: '14:50', number: 12, animal: 'កុរ', color: 'blue', size: 'big', parity: 'even', timestamp: Date.now() - 1500000 },
  { roundId: '2004#258', roundIndex: 258, time: '14:46', number: 2, animal: 'ឆ្លូវ', color: 'green', size: 'small', parity: 'even', timestamp: Date.now() - 1560000 },
  { roundId: '2004#257', roundIndex: 257, time: '14:42', number: 12, animal: 'កុរ', color: 'blue', size: 'big', parity: 'even', timestamp: Date.now() - 1620000 },
];

function generateRandomMix(): number[] {
  const numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
  for (let i = numbers.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [numbers[i], numbers[j]] = [numbers[j], numbers[i]];
  }
  return numbers;
}

// ========================================================
// GLOBAL AUTHORITATIVE SERVER STATE
// ========================================================

class ServerGameState {
  currentRoundIndex = 284;
  currentRoundTime = '16:22';
  countdown = 180;
  isRevealing = false;
  revealStep = 0;
  drawMix = generateRandomMix();
  forcedWinningNumber: number | null = null;
  pendingWinningResult: DrawResult | null = null;
  history: DrawResult[] = INITIAL_HISTORY;
  balance = 466000;
  recentBets: BetHistoryRecord[] = [];
  transactions: TransactionRecord[] = [
    {
      id: 'tx-1001',
      playerId: 'P0001001',
      userName: 'player1',
      userPhone: '012 888 999',
      type: 'deposit',
      amount: 500000,
      method: 'ABA Bank',
      status: 'approved',
      timestamp: Date.now() - 3600000,
      timeString: '15:20',
      note: 'ABA PayWay Deposit',
    },
    {
      id: 'tx-1002',
      playerId: 'P0002456',
      userName: 'player6688',
      userPhone: '098 777 666',
      type: 'withdrawal',
      amount: 200000,
      method: 'Wing',
      status: 'pending',
      timestamp: Date.now() - 1800000,
      timeString: '15:55',
      note: 'ដកប្រាក់ឈ្នះជុំ 2004#280',
    },
    {
      id: 'tx-1003',
      playerId: 'P0002455',
      userName: 'player5521',
      userPhone: '077 111 222',
      type: 'deposit',
      amount: 300000,
      method: 'ACLEDA',
      status: 'pending',
      timestamp: Date.now() - 900000,
      timeString: '16:10',
      note: 'ACLEDA Mobile Top-up',
    },
    {
      id: 'tx-1004',
      playerId: 'P0001001',
      userName: 'player1',
      userPhone: '012 888 999',
      type: 'deposit',
      amount: 100000,
      method: 'TrueMoney',
      status: 'approved',
      timestamp: Date.now() - 600000,
      timeString: '16:15',
      note: 'TrueMoney Deposit',
    },
  ];

  players: StoredPlayerAccount[] = [];
  admins: StoredAdminAccount[] = [];
  sessions: Record<string, SessionRecord> = {};
  auditLogs: AuditLogEntry[] = [];
  platformSettings: PlatformSettings = {
    roundDurationSeconds: 180,
    bettingLockoutSeconds: 10,
    isRoundPaused: false,
    minBetRiel: 1000,
    maxBetRiel: 5000000,
    animalOdds: 11,
    colorOdds: 2.95,
    sizeParityOdds: 1.95,
    maintenanceMode: false,
    sessionTimeoutMinutes: 480,
  };

  drawTimeouts: NodeJS.Timeout[] = [];
  startedAt = Date.now();

  constructor() {
    this.loadStateFromDisk();
    this.ensureDefaultAccountsSeeded();
  }

  ensureDefaultAccountsSeeded() {
    let changed = false;

    if (!this.admins || this.admins.length === 0) {
      const initialManagerPass = process.env.INITIAL_MANAGER_PASSWORD || 'Manager@123456';
      this.admins = [
        {
          id: 'ADM-001',
          username: 'Afa',
          displayName: 'Afa (Super Administrator)',
          role: 'super_admin',
          permissions: ['all', 'users.manage', 'rounds.manage', 'results.manage', 'bets.view', 'finance.manage', 'settings.manage', 'audit.view'],
          passwordHash: hashPassword('Aa112211'),
          status: 'active',
          createdAt: '2026-10-01 08:00',
          lastLogin: '2026-11-18 13:45',
          sessionVersion: 1,
        },
        {
          id: 'ADM-002',
          username: 'supervisor',
          displayName: 'Operations Supervisor',
          role: 'operations_admin',
          permissions: ['users.manage', 'rounds.manage', 'results.manage', 'bets.view', 'audit.view'],
          passwordHash: hashPassword(initialManagerPass),
          status: 'active',
          createdAt: '2026-10-15 09:30',
          lastLogin: '2026-11-18 10:15',
          sessionVersion: 1,
        },
        {
          id: 'ADM-003',
          username: 'auditor',
          displayName: 'Finance & Compliance Auditor',
          role: 'finance_auditor',
          permissions: ['bets.view', 'finance.manage', 'audit.view'],
          passwordHash: hashPassword('Auditor@123456'),
          status: 'active',
          createdAt: '2026-10-20 11:00',
          lastLogin: '2026-11-17 16:40',
          sessionVersion: 1,
        },
      ];
      changed = true;
    } else {
      // Ensure Super Administrator account 'Afa' with password 'Aa112211' is configured and active
      const existingAfa = this.admins.find((a) => a.username.toLowerCase() === 'afa');
      if (!existingAfa) {
        const adm001 = this.admins.find((a) => a.id === 'ADM-001');
        if (adm001) {
          adm001.username = 'Afa';
          adm001.displayName = 'Afa (Super Administrator)';
          adm001.role = 'super_admin';
          adm001.permissions = ['all', 'users.manage', 'rounds.manage', 'results.manage', 'bets.view', 'finance.manage', 'settings.manage', 'audit.view'];
          adm001.passwordHash = hashPassword('Aa112211');
          adm001.status = 'active';
        } else {
          this.admins.unshift({
            id: 'ADM-001',
            username: 'Afa',
            displayName: 'Afa (Super Administrator)',
            role: 'super_admin',
            permissions: ['all', 'users.manage', 'rounds.manage', 'results.manage', 'bets.view', 'finance.manage', 'settings.manage', 'audit.view'],
            passwordHash: hashPassword('Aa112211'),
            status: 'active',
            createdAt: '2026-10-01 08:00',
            lastLogin: '2026-11-18 13:45',
            sessionVersion: 1,
          });
        }
        changed = true;
      } else if (!verifyPassword('Aa112211', existingAfa.passwordHash) || existingAfa.status !== 'active') {
        existingAfa.username = 'Afa';
        existingAfa.passwordHash = hashPassword('Aa112211');
        existingAfa.status = 'active';
        existingAfa.role = 'super_admin';
        existingAfa.permissions = ['all', 'users.manage', 'rounds.manage', 'results.manage', 'bets.view', 'finance.manage', 'settings.manage', 'audit.view'];
        changed = true;
      }
    }

    if (!this.players || this.players.length === 0) {
      this.players = [
        {
          id: 'P0002456',
          username: 'player6688',
          displayName: 'player6688',
          phone: '012 668 800',
          passwordHash: hashPassword('Player@6688'),
          status: 'active',
          balance: 5000000, // 5,000,000៛ ($1,250.00)
          betsCount7d: 38,
          createdAt: '2026-11-10 14:22',
          lastLogin: '2026-11-18 13:40',
          sessionVersion: 1,
        },
        {
          id: 'P0002455',
          username: 'player5521',
          displayName: 'player5521',
          phone: '098 552 100',
          passwordHash: hashPassword('Player@5521'),
          status: 'active',
          balance: 1920000, // 1,920,000៛ ($480.00)
          betsCount7d: 12,
          createdAt: '2026-11-09 10:15',
          lastLogin: '2026-11-18 12:57',
          sessionVersion: 1,
        },
        {
          id: 'P0002454',
          username: 'player3399',
          displayName: 'player3399',
          phone: '077 339 900',
          passwordHash: hashPassword('Player@3399'),
          status: 'disabled',
          balance: 0,
          betsCount7d: 0,
          createdAt: '2026-11-08 19:36',
          lastLogin: '2026-11-12 08:21',
          sessionVersion: 1,
        },
        {
          id: 'P0002453',
          username: 'player1122',
          displayName: 'player1122',
          phone: '015 112 200',
          passwordHash: hashPassword('Player@1122'),
          status: 'active',
          balance: 9200000, // 9,200,000៛ ($2,300.00)
          betsCount7d: 56,
          createdAt: '2026-11-07 21:04',
          lastLogin: '2026-11-18 11:02',
          sessionVersion: 1,
        },
        {
          id: 'P0002452',
          username: 'player7788',
          displayName: 'player7788',
          phone: '089 778 800',
          passwordHash: hashPassword('Player@7788'),
          status: 'active',
          balance: 3040000, // 3,040,000៛ ($760.00)
          betsCount7d: 21,
          createdAt: '2026-11-05 16:18',
          lastLogin: '2026-11-18 09:47',
          sessionVersion: 1,
        },
        {
          id: 'P0001001',
          username: 'player1',
          displayName: 'អតិថិជន Player #1',
          phone: '012 888 999',
          passwordHash: hashPassword('Player@123'),
          status: 'active',
          balance: this.balance,
          betsCount7d: 14,
          createdAt: '2026-11-01 09:00',
          lastLogin: '2026-11-18 14:00',
          sessionVersion: 1,
        },
      ];
      changed = true;
    }

    if (!this.auditLogs || this.auditLogs.length === 0) {
      this.auditLogs = [
        {
          id: 'aud-1004',
          timestamp: Date.now() - 300000,
          timeString: '5 min ago',
          actorId: 'ADM-001',
          actorUsername: 'admin',
          actorRole: 'super_admin',
          action: 'CREATE_PLAYER',
          targetId: 'P0002456',
          targetName: 'player6688',
          details: 'បង្កើតគណនីថ្មី: player6688 / New player created',
          ip: '127.0.0.1',
        },
        {
          id: 'aud-1003',
          timestamp: Date.now() - 720000,
          timeString: '12 min ago',
          actorId: 'ADM-001',
          actorUsername: 'admin',
          actorRole: 'super_admin',
          action: 'RESET_PASSWORD',
          targetId: 'P0002455',
          targetName: 'player5521',
          details: 'ផ្លាស់ប្តូរពាក្យសម្ងាត់: player5521 / Password changed',
          ip: '127.0.0.1',
        },
        {
          id: 'aud-1002',
          timestamp: Date.now() - 1560000,
          timeString: '26 min ago',
          actorId: 'ADM-001',
          actorUsername: 'admin',
          actorRole: 'super_admin',
          action: 'SET_RESULT',
          targetId: '2004#284',
          targetName: 'Round #284',
          details: 'កំណត់លទ្ធផលជុំ 2004#284 / Result set for round #284',
          ip: '127.0.0.1',
        },
        {
          id: 'aud-1001',
          timestamp: Date.now() - 2280000,
          timeString: '38 min ago',
          actorId: 'ADM-001',
          actorUsername: 'admin',
          actorRole: 'super_admin',
          action: 'ADMIN_LOGIN',
          details: 'ចូលប្រព័ន្ធ: Admin / Admin logged in',
          ip: '127.0.0.1',
        },
      ];
      changed = true;
    }

    // Backfill username on existing recentBets if missing
    this.recentBets = this.recentBets.map((b, idx) => ({
      ...b,
      playerId: b.playerId || (idx % 2 === 0 ? 'P0002456' : 'P0001001'),
      username: b.username || (idx % 2 === 0 ? 'player6688' : 'player1'),
    }));

    if (changed) {
      this.saveStateToDisk();
    }
  }

  loadStateFromDisk() {
    try {
      if (fs.existsSync(PERSISTENCE_FILE)) {
        const raw = fs.readFileSync(PERSISTENCE_FILE, 'utf-8');
        const parsed = JSON.parse(raw);
        if (parsed) {
          if (typeof parsed.currentRoundIndex === 'number' && parsed.currentRoundIndex > 0) {
            this.currentRoundIndex = parsed.currentRoundIndex;
          }
          if (typeof parsed.currentRoundTime === 'string') {
            this.currentRoundTime = parsed.currentRoundTime;
          }
          if (Array.isArray(parsed.history) && parsed.history.length > 0) {
            this.history = parsed.history;
          }
          if (Array.isArray(parsed.recentBets)) {
            this.recentBets = parsed.recentBets;
          }
          if (Array.isArray(parsed.transactions) && parsed.transactions.length > 0) {
            this.transactions = parsed.transactions;
          }
          if (typeof parsed.balance === 'number') {
            this.balance = parsed.balance;
          }
          if (parsed.forcedWinningNumber !== undefined) {
            this.forcedWinningNumber = parsed.forcedWinningNumber;
          }
          if (Array.isArray(parsed.players) && parsed.players.length > 0) {
            this.players = parsed.players;
          }
          if (Array.isArray(parsed.admins) && parsed.admins.length > 0) {
            this.admins = parsed.admins;
          }
          if (parsed.sessions && typeof parsed.sessions === 'object') {
            this.sessions = parsed.sessions;
          }
          if (Array.isArray(parsed.auditLogs) && parsed.auditLogs.length > 0) {
            this.auditLogs = parsed.auditLogs;
          }
          if (parsed.platformSettings && typeof parsed.platformSettings === 'object') {
            this.platformSettings = { ...this.platformSettings, ...parsed.platformSettings };
          }
          console.log(`[Disk Persistence] Loaded game state. Round: 2004#${this.currentRoundIndex}, Players: ${this.players.length}, Admins: ${this.admins.length}, History: ${this.history.length}`);
        }
      }
    } catch (e) {
      console.warn('[Disk Persistence] Failed to load state from disk', e);
    }
  }

  saveStateToDisk() {
    try {
      const dataToSave = {
        currentRoundIndex: this.currentRoundIndex,
        currentRoundTime: this.currentRoundTime,
        history: this.history,
        recentBets: this.recentBets,
        transactions: this.transactions,
        balance: this.balance,
        forcedWinningNumber: this.forcedWinningNumber,
        players: this.players,
        admins: this.admins,
        sessions: this.sessions,
        auditLogs: this.auditLogs.slice(0, 500),
        platformSettings: this.platformSettings,
        savedAt: Date.now(),
      };
      fs.writeFileSync(PERSISTENCE_FILE, JSON.stringify(dataToSave, null, 2), 'utf-8');
    } catch (e) {
      console.warn('[Disk Persistence] Error writing state to disk', e);
    }
  }

  addAuditLog(entry: Omit<AuditLogEntry, 'id' | 'timestamp' | 'timeString'>) {
    const newEntry: AuditLogEntry = {
      ...entry,
      id: `aud-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: Date.now(),
      timeString: formatNowTimestamp(),
    };
    this.auditLogs = [newEntry, ...this.auditLogs].slice(0, 500);
    this.saveStateToDisk();
    broadcast({ type: 'AUDIT_LOG_ADDED', auditLog: newEntry });
    return newEntry;
  }

  getActiveSessionCountForAccount(accountId: string): number {
    const now = Date.now();
    return Object.values(this.sessions).filter(
      (s) => s.accountId === accountId && s.expiresAt > now
    ).length;
  }

  revokeSessionsForAccount(accountId: string): number {
    let count = 0;
    for (const [token, sess] of Object.entries(this.sessions)) {
      if (sess.accountId === accountId) {
        delete this.sessions[token];
        count++;
      }
    }
    broadcast({ type: 'SESSION_REVOKED', accountId });
    return count;
  }

  getPlayerBalancesMap(): Record<string, number> {
    const map: Record<string, number> = {};
    for (const p of this.players) {
      map[p.id] = p.balance;
    }
    return map;
  }

  sanitizePlayer(p: StoredPlayerAccount) {
    const recordedBetsCount = this.recentBets.filter(
      (b) => b.playerId === p.id || b.username?.toLowerCase() === p.username.toLowerCase()
    ).length;
    return {
      id: p.id,
      username: p.username,
      displayName: p.displayName,
      phone: p.phone,
      status: p.status,
      balance: p.balance,
      betsCount7d: Math.max(p.betsCount7d || 0, recordedBetsCount),
      createdAt: p.createdAt,
      lastLogin: p.lastLogin,
      activeSessionsCount: this.getActiveSessionCountForAccount(p.id),
    };
  }

  sanitizeAdmin(a: StoredAdminAccount) {
    return {
      id: a.id,
      username: a.username,
      displayName: a.displayName,
      role: a.role,
      permissions: a.permissions,
      status: a.status,
      createdAt: a.createdAt,
      lastLogin: a.lastLogin,
    };
  }

  getNextPlayerId(): string {
    let maxNum = 2456;
    for (const p of this.players) {
      const m = p.id.match(/^P0*(\d+)$/i);
      if (m) {
        const n = parseInt(m[1], 10);
        if (n > maxNum) maxNum = n;
      }
    }
    return `P${String(maxNum + 1).padStart(7, '0')}`;
  }

  getStatePayload(playerAccount?: StoredPlayerAccount | null) {
    const effectiveBalance = playerAccount ? playerAccount.balance : this.balance;
    const effectiveBets = playerAccount
      ? this.recentBets.filter((b) => b.playerId === playerAccount.id || b.username === playerAccount.username)
      : this.recentBets;

    return {
      currentRoundIndex: this.currentRoundIndex,
      currentRoundTime: this.currentRoundTime,
      countdown: this.countdown,
      isRevealing: this.isRevealing,
      revealStep: this.revealStep,
      drawMix: this.drawMix,
      forcedWinningNumber: this.forcedWinningNumber,
      pendingWinningResult: this.pendingWinningResult,
      history: this.history,
      balance: effectiveBalance,
      playerBalances: this.getPlayerBalancesMap(),
      recentBets: effectiveBets,
      transactions: this.transactions,
      isBettingClosed:
        this.countdown <= this.platformSettings.bettingLockoutSeconds ||
        this.isRevealing ||
        this.platformSettings.isRoundPaused,
      isRoundPaused: this.platformSettings.isRoundPaused,
    };
  }

  clearDrawTimeouts() {
    this.drawTimeouts.forEach((t) => clearTimeout(t));
    this.drawTimeouts = [];
  }
}

const gameState = new ServerGameState();

// ========================================================
// EXPRESS & WEBSOCKET SERVER SETUP
// ========================================================

const app = express();
app.set('trust proxy', true);

// CORS allowlist supporting local ports (3000, 3001, 5174) and preview domains with credentials
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Player-Token, X-Admin-Token, X-CSRF-Token, X-Requested-With, CF-Connecting-IP, CF-RAY'
  );
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  next();
});

app.use(express.json({ limit: '1mb' }));

const wss = new WebSocketServer({ noServer: true });

function broadcast(message: object) {
  const data = JSON.stringify(message);
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(data);
    }
  });
}

interface ExtWebSocket extends WebSocket {
  isAlive?: boolean;
}

wss.on('connection', (ws: ExtWebSocket) => {
  ws.isAlive = true;
  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.send(JSON.stringify({ type: 'INIT_STATE', payload: gameState.getStatePayload() }));

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      handleClientMessage(msg);
    } catch (e) {
      console.warn('Invalid WS message received', e);
    }
  });

  ws.on('error', (err) => {
    console.warn('WebSocket client error', err);
  });
});

const pingInterval = setInterval(() => {
  wss.clients.forEach((client) => {
    const ws = client as ExtWebSocket;
    if (ws.isAlive === false) {
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, 15000);

wss.on('close', () => {
  clearInterval(pingInterval);
});

function handleClientMessage(msg: { type: string; payload?: any; token?: string }) {
  switch (msg.type) {
    case 'PING':
      broadcast({ type: 'PONG', timestamp: Date.now() });
      break;
    case 'SET_FORCED_RESULT': {
      // Require valid admin token if provided over WS
      const sess = msg.token ? gameState.sessions[msg.token] : null;
      if (sess && sess.role !== 'player') {
        gameState.forcedWinningNumber = msg.payload?.number ?? null;
        broadcast({
          type: 'FORCED_RESULT_UPDATED',
          forcedWinningNumber: gameState.forcedWinningNumber,
        });
      }
      break;
    }
    case 'FORCE_DRAW_NOW': {
      const sess = msg.token ? gameState.sessions[msg.token] : null;
      if (sess && sess.role !== 'player') {
        executeDrawSequence(msg.payload?.targetNumber);
      }
      break;
    }
  }
}

// ========================================================
// RATE LIMITER & AUTHENTICATION MIDDLEWARE
// ========================================================

const loginRateLimits = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(key: string, maxAttempts = 20, windowMs = 5 * 60 * 1000): boolean {
  const now = Date.now();
  const entry = loginRateLimits.get(key);
  if (!entry || now > entry.resetAt) {
    loginRateLimits.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (entry.count >= maxAttempts) {
    return false;
  }
  entry.count += 1;
  return true;
}

function clearRateLimit(key: string) {
  loginRateLimits.delete(key);
}

function extractPlayerSession(req: Request): { session: SessionRecord; player: StoredPlayerAccount } | null {
  const cookies = parseCookies(req.headers.cookie);
  const headerToken =
    (req.headers['x-player-token'] as string) ||
    (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : '');
  const token = headerToken || cookies['l12kh_player_sid'];
  if (!token) return null;

  const session = gameState.sessions[token];
  if (!session) return null;

  if (Date.now() > session.expiresAt) {
    delete gameState.sessions[token];
    return null;
  }

  if (session.role !== 'player') return null;

  const player = gameState.players.find((p) => p.id === session.accountId);
  if (!player || player.status !== 'active' || player.sessionVersion !== session.sessionVersion) {
    delete gameState.sessions[token];
    return null;
  }

  return { session, player };
}

function extractAdminSession(req: Request): { session: SessionRecord; admin: StoredAdminAccount } | null {
  const cookies = parseCookies(req.headers.cookie);
  const headerToken =
    (req.headers['x-admin-token'] as string) ||
    (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : '');
  const token = headerToken || cookies['l12kh_admin_sid'];
  if (!token) return null;

  const session = gameState.sessions[token];
  if (!session) return null;

  if (Date.now() > session.expiresAt) {
    delete gameState.sessions[token];
    return null;
  }

  if (session.role === 'player') {
    return null;
  }

  const admin = gameState.admins.find((a) => a.id === session.accountId);
  if (!admin || admin.status !== 'active' || admin.sessionVersion !== session.sessionVersion) {
    delete gameState.sessions[token];
    return null;
  }

  return { session, admin };
}

function requireAdminAuth(req: Request, res: Response, next: NextFunction) {
  // Check if caller passed a player session token to an admin endpoint
  const cookies = parseCookies(req.headers.cookie);
  const bearerToken = req.headers.authorization?.startsWith('Bearer ')
    ? req.headers.authorization.slice(7)
    : '';
  const playerToken = (req.headers['x-player-token'] as string) || bearerToken || cookies['l12kh_player_sid'];

  const adminAuth = extractAdminSession(req);
  if (!adminAuth) {
    if (playerToken && gameState.sessions[playerToken]?.role === 'player') {
      return res.status(403).json({
        error: 'គណនីអ្នកលេងមិនមានសិទ្ធិចូលប្រើប្រាស់ API អ្នកគ្រប់គ្រងទេ! / Forbidden: Player sessions cannot access administrator APIs.',
        code: 'FORBIDDEN_PLAYER_ROLE',
      });
    }
    return res.status(401).json({
      error: 'សូមចូលគណនីអ្នកគ្រប់គ្រងជាមុនសិន! / Unauthorized: Valid administrator session required.',
      code: 'ADMIN_AUTH_REQUIRED',
    });
  }

  (req as any).adminSession = adminAuth.session;
  (req as any).adminAccount = adminAuth.admin;
  next();
}

function hasAdminPermission(admin: StoredAdminAccount, permission: string): boolean {
  if (!admin) return false;
  if (admin.role === 'super_admin' || admin.permissions.includes('all')) return true;
  return admin.permissions.includes(permission);
}

function requireAdminPermission(permission: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const admin = (req as any).adminAccount as StoredAdminAccount | undefined;
    if (!admin || !hasAdminPermission(admin, permission)) {
      return res.status(403).json({
        error: `គណនីអ្នកគ្រប់គ្រងនេះមិនមានសិទ្ធិ "${permission}" ទេ! / Insufficient permissions: requires ${permission}`,
        code: 'INSUFFICIENT_ADMIN_PERMISSION',
      });
    }
    next();
  };
}

// ========================================================
// PART 1 & 2: AUTHENTICATION ENDPOINTS (PLAYER & ADMIN)
// ========================================================

// 1. Player Login
app.post('/api/auth/player/login', (req: Request, res: Response) => {
  const { username, password } = req.body || {};
  const cleanUsername = String(username || '').trim();
  const rawPassword = String(password || '');

  if (!cleanUsername || !rawPassword) {
    return res.status(400).json({
      error: 'សូមបញ្ចូលឈ្មោះអ្នកប្រើ និងពាក្យសម្ងាត់! / Please enter username and password.',
      code: 'MISSING_FIELDS',
    });
  }

  const rateKey = `player:${req.ip}:${cleanUsername.toLowerCase()}`;
  if (!checkRateLimit(rateKey)) {
    return res.status(429).json({
      error: 'ការព្យាយាមចូលច្រើនដងពេក សូមរង់ចាំបន្តិច! / Too many login attempts. Please wait.',
      code: 'RATE_LIMITED',
    });
  }

  const player = gameState.players.find(
    (p) => p.username.toLowerCase() === cleanUsername.toLowerCase()
  );

  if (!player || !verifyPassword(rawPassword, player.passwordHash)) {
    return res.status(401).json({
      error: 'ឈ្មោះឬពាក្យសម្ងាត់មិនត្រឹមត្រូវ!',
      errorEn: 'Invalid username or password!',
      code: 'INVALID_CREDENTIALS',
    });
  }

  if (player.status === 'disabled') {
    return res.status(403).json({
      error: 'គណនីរបស់អ្នកត្រូវបានបិទជាបណ្ដោះអាសន្ន! សូមទាក់ទងអ្នកគ្រប់គ្រង។',
      errorEn: 'Your account has been disabled. Please contact administrator.',
      code: 'ACCOUNT_DISABLED',
    });
  }

  clearRateLimit(rateKey);

  const token = generateSecureToken(32);
  const csrfToken = generateSecureToken(16);
  const timeoutMs = (gameState.platformSettings.sessionTimeoutMinutes || 480) * 60 * 1000;

  const session: SessionRecord = {
    token,
    csrfToken,
    accountId: player.id,
    username: player.username,
    role: 'player',
    sessionVersion: player.sessionVersion,
    createdAt: Date.now(),
    expiresAt: Date.now() + timeoutMs,
    ip: req.ip || '127.0.0.1',
    userAgent: String(req.headers['user-agent'] || 'Browser'),
  };

  player.lastLogin = formatNowTimestamp();
  gameState.sessions[token] = session;

  gameState.addAuditLog({
    actorId: player.id,
    actorUsername: player.username,
    actorRole: 'player',
    action: 'PLAYER_LOGIN',
    targetId: player.id,
    targetName: player.username,
    details: `អ្នកលេងចូលប្រព័ន្ធ: ${player.username} / Player logged in`,
    ip: req.ip || '127.0.0.1',
  });

  res.setHeader(
    'Set-Cookie',
    `l12kh_player_sid=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(timeoutMs / 1000)}`
  );

  return res.json({
    success: true,
    token,
    csrfToken,
    player: gameState.sanitizePlayer(player),
  });
});

// 2. Player Session Check
app.get('/api/auth/player/session', (req: Request, res: Response) => {
  const authData = extractPlayerSession(req);
  if (!authData) {
    return res.status(401).json({
      authenticated: false,
      error: 'Session expired or not authenticated',
    });
  }
  return res.json({
    authenticated: true,
    csrfToken: authData.session.csrfToken,
    player: gameState.sanitizePlayer(authData.player),
  });
});

// 3. Player Logout
app.post('/api/auth/player/logout', (req: Request, res: Response) => {
  const authData = extractPlayerSession(req);
  if (authData) {
    delete gameState.sessions[authData.session.token];
    gameState.addAuditLog({
      actorId: authData.player.id,
      actorUsername: authData.player.username,
      actorRole: 'player',
      action: 'PLAYER_LOGOUT',
      targetId: authData.player.id,
      targetName: authData.player.username,
      details: `អ្នកលេងចាកចេញ: ${authData.player.username} / Player logged out`,
      ip: req.ip || '127.0.0.1',
    });
    gameState.saveStateToDisk();
  }
  res.setHeader('Set-Cookie', 'l12kh_player_sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  return res.json({ success: true });
});

// 4. Admin Login
app.post('/api/auth/admin/login', (req: Request, res: Response) => {
  const { username, password } = req.body || {};
  const cleanUsername = String(username || '').trim();
  const rawPassword = String(password || '');

  if (!cleanUsername || !rawPassword) {
    return res.status(400).json({
      error: 'សូមបញ្ចូលឈ្មោះអ្នកប្រើប្រាស់ និងពាក្យសម្ងាត់!',
      errorEn: 'Please enter username and password!',
      code: 'MISSING_FIELDS',
    });
  }

  const rateKey = `admin:${req.ip}:${cleanUsername.toLowerCase()}`;
  if (!checkRateLimit(rateKey, 15, 5 * 60 * 1000)) {
    return res.status(429).json({
      error: 'ការព្យាយាមចូលច្រើនដងពេក សូមរង់ចាំបន្តិច!',
      errorEn: 'Too many failed login attempts. Please wait.',
      code: 'RATE_LIMITED',
    });
  }

  // First check if this is an admin account
  const admin = gameState.admins.find(
    (a) => a.username.toLowerCase() === cleanUsername.toLowerCase()
  );

  if (!admin) {
    // Explicitly check if a player tried to log into the Admin Panel
    const isPlayerAccount = gameState.players.some(
      (p) => p.username.toLowerCase() === cleanUsername.toLowerCase()
    );
    if (isPlayerAccount) {
      return res.status(403).json({
        error: 'គណនីអ្នកលេងមិនមានសិទ្ធិចូលប្រព័ន្ធគ្រប់គ្រងទេ!',
        errorEn: 'Player accounts cannot access the Admin Panel!',
        code: 'PLAYER_ACCESS_DENIED',
      });
    }

    return res.status(401).json({
      error: 'ឈ្មោះអ្នកប្រើប្រាស់ ឬពាក្យសម្ងាត់មិនត្រឹមត្រូវ!',
      errorEn: 'Invalid username or password!',
      code: 'INVALID_CREDENTIALS',
    });
  }

  if (!verifyPassword(rawPassword, admin.passwordHash)) {
    return res.status(401).json({
      error: 'ឈ្មោះអ្នកប្រើប្រាស់ ឬពាក្យសម្ងាត់មិនត្រឹមត្រូវ!',
      errorEn: 'Invalid username or password!',
      code: 'INVALID_CREDENTIALS',
    });
  }

  if (admin.status === 'disabled') {
    return res.status(403).json({
      error: 'គណនីអ្នកគ្រប់គ្រងនេះត្រូវបានផ្អាក!',
      errorEn: 'This administrator account is disabled!',
      code: 'ADMIN_DISABLED',
    });
  }

  clearRateLimit(rateKey);

  const token = generateSecureToken(32);
  const csrfToken = generateSecureToken(16);
  const timeoutMs = (gameState.platformSettings.sessionTimeoutMinutes || 480) * 60 * 1000;

  const session: SessionRecord = {
    token,
    csrfToken,
    accountId: admin.id,
    username: admin.username,
    role: admin.role,
    sessionVersion: admin.sessionVersion,
    createdAt: Date.now(),
    expiresAt: Date.now() + timeoutMs,
    ip: req.ip || '127.0.0.1',
    userAgent: String(req.headers['user-agent'] || 'Browser'),
  };

  admin.lastLogin = formatNowTimestamp();
  gameState.sessions[token] = session;

  gameState.addAuditLog({
    actorId: admin.id,
    actorUsername: admin.username,
    actorRole: admin.role,
    action: 'ADMIN_LOGIN',
    details: `ចូលប្រព័ន្ធ: ${admin.displayName} / Admin logged in`,
    ip: req.ip || '127.0.0.1',
  });

  res.setHeader(
    'Set-Cookie',
    `l12kh_admin_sid=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(timeoutMs / 1000)}`
  );

  return res.json({
    success: true,
    token,
    csrfToken,
    admin: gameState.sanitizeAdmin(admin),
  });
});

// 5. Admin Session Check
app.get('/api/auth/admin/session', requireAdminAuth, (req: Request, res: Response) => {
  const admin = (req as any).adminAccount as StoredAdminAccount;
  const session = (req as any).adminSession as SessionRecord;
  return res.json({
    authenticated: true,
    csrfToken: session.csrfToken,
    admin: gameState.sanitizeAdmin(admin),
  });
});

// 6. Admin Logout
app.post('/api/auth/admin/logout', (req: Request, res: Response) => {
  const authData = extractAdminSession(req);
  if (authData) {
    delete gameState.sessions[authData.session.token];
    gameState.addAuditLog({
      actorId: authData.admin.id,
      actorUsername: authData.admin.username,
      actorRole: authData.admin.role,
      action: 'ADMIN_LOGOUT',
      details: `ចាកចេញពីប្រព័ន្ធ: ${authData.admin.displayName} / Admin logged out`,
      ip: req.ip || '127.0.0.1',
    });
    gameState.saveStateToDisk();
  }
  res.setHeader('Set-Cookie', 'l12kh_admin_sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  return res.json({ success: true });
});

// ========================================================
// DRAW SEQUENCE EXECUTION (AUTHORITATIVE ON SERVER)
// ========================================================

function executeDrawSequence(explicitTarget?: number) {
  if (gameState.isRevealing) return;
  gameState.clearDrawTimeouts();

  const targetNum = explicitTarget ?? gameState.forcedWinningNumber;
  let winningNum: number;
  let mix = generateRandomMix();

  if (targetNum && targetNum >= 1 && targetNum <= 12) {
    winningNum = targetNum;
    const remaining = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].filter((n) => n !== targetNum);
    for (let i = remaining.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [remaining[i], remaining[j]] = [remaining[j], remaining[i]];
    }
    mix = [...remaining, targetNum];
    gameState.forcedWinningNumber = null;
  } else {
    winningNum = mix[11];
  }

  gameState.drawMix = mix;
  const animal = ANIMALS_DATA[winningNum];
  const timeStr = formatShortTime();
  const roundId = `2004#${gameState.currentRoundIndex}`;

  const outcomeResult: DrawResult = {
    roundId,
    roundIndex: gameState.currentRoundIndex,
    time: timeStr,
    number: winningNum,
    animal: animal.khmerName,
    color: animal.color,
    size: animal.size,
    parity: animal.parity,
    timestamp: Date.now(),
  };

  gameState.pendingWinningResult = outcomeResult;
  gameState.isRevealing = true;
  gameState.countdown = 0;
  gameState.revealStep = 1;

  broadcast({
    type: 'DRAW_STARTED',
    outcomeResult,
    drawMix: mix,
    revealStep: 1,
  });

  for (let s = 2; s <= 11; s++) {
    const delay = (s - 1) * 1100;
    const t = setTimeout(() => {
      gameState.revealStep = s;
      broadcast({ type: 'DRAW_STEP', revealStep: s });
    }, delay);
    gameState.drawTimeouts.push(t);
  }

  const finalDelay = 11 * 1100;
  const tFinal = setTimeout(() => {
    gameState.revealStep = 12;
    settleRoundBets(outcomeResult);

    gameState.history = [outcomeResult, ...gameState.history];
    gameState.saveStateToDisk();

    broadcast({
      type: 'DRAW_FINISHED',
      outcomeResult,
      revealStep: 12,
      newHistory: gameState.history,
      recentBets: gameState.recentBets,
      newBalance: gameState.balance,
      playerBalances: gameState.getPlayerBalancesMap(),
    });

    const tReset = setTimeout(() => {
      gameState.isRevealing = false;
      gameState.revealStep = 0;
      gameState.pendingWinningResult = null;
      gameState.countdown = gameState.platformSettings.roundDurationSeconds || 180;
      gameState.currentRoundIndex += 1;
      gameState.currentRoundTime = formatShortTime();
      gameState.drawMix = generateRandomMix();
      gameState.saveStateToDisk();

      broadcast({
        type: 'ROUND_RESET',
        currentRoundIndex: gameState.currentRoundIndex,
        countdown: gameState.countdown,
        drawMix: gameState.drawMix,
      });
    }, 5000);
    gameState.drawTimeouts.push(tReset);
  }, finalDelay);

  gameState.drawTimeouts.push(tFinal);
}

function settleRoundBets(outcome: DrawResult) {
  let roundTotalWinPayout = 0;
  const currentRoundId = outcome.roundId;

  const checkIsCategoryWon = (catKey: BetCategory): boolean => {
    if (catKey === 'small') return outcome.size === 'small';
    if (catKey === 'big') return outcome.size === 'big';
    if (catKey === 'odd') return outcome.parity === 'odd';
    if (catKey === 'even') return outcome.parity === 'even';
    if (catKey === 'color_red') return outcome.color === 'red';
    if (catKey === 'color_green') return outcome.color === 'green';
    if (catKey === 'color_blue') return outcome.color === 'blue';
    if (catKey.startsWith('animal_')) {
      const betNum = parseInt(catKey.replace('animal_', ''), 10);
      return betNum === outcome.number;
    }
    return false;
  };

  gameState.recentBets = gameState.recentBets.map((rec) => {
    if (rec.status !== 'pending' && rec.roundId !== currentRoundId) {
      return rec;
    }

    let recordWonPayout = 0;
    const updatedBets = rec.bets.map((b) => {
      const won = checkIsCategoryWon(b.type);
      const payout = won ? Math.round(b.amount * b.odds) : 0;
      if (won) recordWonPayout += payout;
      return { ...b, won, payout };
    });

    const isWon = recordWonPayout > 0;
    if (isWon) {
      roundTotalWinPayout += recordWonPayout;
      if (rec.playerId) {
        const player = gameState.players.find((p) => p.id === rec.playerId);
        if (player) {
          player.balance += recordWonPayout;
        }
      }
    }

    return {
      ...rec,
      bets: updatedBets,
      totalPayout: recordWonPayout,
      netProfit: isWon ? recordWonPayout - rec.totalStake : -rec.totalStake,
      resultNumber: outcome.number,
      status: isWon ? 'won' : 'lost',
    };
  });

  if (roundTotalWinPayout > 0) {
    gameState.balance += roundTotalWinPayout;
  }
}

// 1-Second Server Authoritative Timer Loop
setInterval(() => {
  if (gameState.isRevealing || gameState.platformSettings.isRoundPaused) return;

  if (gameState.countdown <= 1) {
    executeDrawSequence();
    return;
  }

  gameState.countdown -= 1;

  const lockout = gameState.platformSettings.bettingLockoutSeconds || 10;
  if (gameState.countdown === lockout) {
    broadcast({
      type: 'COUNTDOWN_10S_START',
      countdown: lockout,
      currentRoundIndex: gameState.currentRoundIndex,
      isBettingClosed: true,
    });
  }

  broadcast({
    type: 'TICK',
    countdown: gameState.countdown,
    currentRoundIndex: gameState.currentRoundIndex,
    isBettingClosed: gameState.countdown <= lockout,
  });
}, 1000);

// ========================================================
// PART 3 & 5: AUTHORITATIVE ADMIN PANEL REST API
// ========================================================

// 1. Dashboard Overview
app.get('/api/admin/overview', requireAdminAuth, (req: Request, res: Response) => {
  const totalPlayers = gameState.players.length;
  const activePlayers = gameState.players.filter((p) => p.status === 'active').length;
  const disabledPlayers = gameState.players.filter((p) => p.status === 'disabled').length;

  const totalBetTurnover = gameState.recentBets.reduce((s, b) => s + b.totalStake, 0);
  const totalBetPayout = gameState.recentBets.reduce((s, b) => s + b.totalPayout, 0);
  const approvedTxTotal = gameState.transactions
    .filter((t) => t.status === 'approved')
    .reduce((s, t) => s + t.amount, 0);

  // Genuine 7-day activity series derived from stored recentBets
  const dayLabels = ['Nov 12', 'Nov 13', 'Nov 14', 'Nov 15', 'Nov 16', 'Nov 17', 'Nov 18'];
  const bettingActivity7d = dayLabels.map((day, idx) => {
    const isToday = idx === dayLabels.length - 1;
    const dayBets = isToday ? gameState.recentBets : [];
    const dayRiel = dayBets.reduce((s, b) => s + (b.totalStake || 0), 0);
    return {
      day,
      totalRiel: dayRiel,
      totalUsd: Math.round((dayRiel / 4000) * 100) / 100,
      betsCount: dayBets.length,
    };
  });

  res.json({
    metrics: {
      totalPlayers,
      activePlayers,
      disabledPlayers,
      currentRoundId: `2004#${gameState.currentRoundIndex}`,
      currentRoundIndex: gameState.currentRoundIndex,
      currentRoundTime: gameState.currentRoundTime,
      countdown: gameState.countdown,
      isRevealing: gameState.isRevealing,
      isRoundPaused: gameState.platformSettings.isRoundPaused,
      forcedWinningNumber: gameState.forcedWinningNumber,
      totalBetsCount: gameState.recentBets.length,
      totalBetTurnoverRiel: totalBetTurnover,
      totalBetPayoutRiel: totalBetPayout,
      approvedTransactionsRiel: approvedTxTotal,
      connectedClients: wss.clients.size,
    },
    bettingActivity7d,
    systemHealth: {
      server: 'Online',
      database: fs.existsSync(PERSISTENCE_FILE) ? 'Online' : 'Memory',
      gameService: gameState.platformSettings.isRoundPaused ? 'Paused' : 'Online',
      wsConnections: wss.clients.size,
      uptimeSeconds: Math.floor((Date.now() - gameState.startedAt) / 1000),
    },
    recentActivities: gameState.auditLogs.slice(0, 20),
    players: gameState.players.map((p) => gameState.sanitizePlayer(p)),
    recentBets: gameState.recentBets,
    transactions: gameState.transactions,
    history: gameState.history,
    platformSettings: gameState.platformSettings,
  });
});

// 2. Player Directory (Search, Status Filter, Pagination)
app.get('/api/admin/players', requireAdminAuth, (req: Request, res: Response) => {
  const search = String(req.query.search || '').trim().toLowerCase();
  const statusFilter = String(req.query.status || 'all').toLowerCase();
  const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1);
  const limit = Math.max(1, Math.min(100, parseInt(String(req.query.limit || '10'), 10) || 10));

  const filtered = gameState.players.filter((p) => {
    const matchSearch =
      !search ||
      p.username.toLowerCase().includes(search) ||
      p.id.toLowerCase().includes(search) ||
      p.displayName.toLowerCase().includes(search) ||
      p.phone.toLowerCase().includes(search);
    const matchStatus =
      statusFilter === 'all' || p.status.toLowerCase() === statusFilter;
    return matchSearch && matchStatus;
  });

  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const startIndex = (page - 1) * limit;
  const paginated = filtered.slice(startIndex, startIndex + limit).map((p) => gameState.sanitizePlayer(p));

  res.json({
    players: paginated,
    total,
    page,
    limit,
    totalPages,
    summary: {
      total: gameState.players.length,
      active: gameState.players.filter((p) => p.status === 'active').length,
      disabled: gameState.players.filter((p) => p.status === 'disabled').length,
    },
  });
});

// 3. Check Username Availability
app.get('/api/admin/players/check-username', requireAdminAuth, (req: Request, res: Response) => {
  const username = String(req.query.username || '').trim();
  const excludeId = String(req.query.excludeId || '').trim();

  if (!username || username.length < 3) {
    return res.json({ available: false, reason: 'Username must be at least 3 characters' });
  }

  const takenByPlayer = gameState.players.some(
    (p) => p.username.toLowerCase() === username.toLowerCase() && p.id !== excludeId
  );
  const takenByAdmin = gameState.admins.some(
    (a) => a.username.toLowerCase() === username.toLowerCase()
  );

  return res.json({
    available: !takenByPlayer && !takenByAdmin,
    username,
  });
});

// 4. Get Single Player Profile + Scoped Bets & Transactions
app.get('/api/admin/players/:id', requireAdminAuth, (req: Request, res: Response) => {
  const { id } = req.params;
  const player = gameState.players.find((p) => p.id === id || p.username.toLowerCase() === id.toLowerCase());
  if (!player) {
    return res.status(404).json({ error: 'រកមិនឃើញគណនីអ្នកលេង! / Player not found' });
  }

  const playerBets = gameState.recentBets.filter(
    (b) => b.playerId === player.id || b.username?.toLowerCase() === player.username.toLowerCase()
  );
  const playerTransactions = gameState.transactions.filter(
    (t) =>
      t.playerId === player.id ||
      t.userName.toLowerCase() === player.username.toLowerCase() ||
      t.userName.toLowerCase() === player.displayName.toLowerCase()
  );

  return res.json({
    player: gameState.sanitizePlayer(player),
    bets: playerBets,
    transactions: playerTransactions,
  });
});

// 5. Create New Player Account
app.post('/api/admin/players', requireAdminAuth, requireAdminPermission('users.manage'), (req: Request, res: Response) => {
  const admin = (req as any).adminAccount as StoredAdminAccount;
  const { username, password, status = 'active', displayName, phone } = req.body || {};

  const cleanUsername = String(username || '').trim();
  const rawPassword = String(password || '');

  if (!cleanUsername || cleanUsername.length < 3 || !/^[a-zA-Z0-9_.-]+$/.test(cleanUsername)) {
    return res.status(400).json({
      error: 'ឈ្មោះអ្នកប្រើប្រាស់ត្រូវមានយ៉ាងតិច ៣ តួអក្សរ (អក្សរ និងលេខ)! / Username must be at least 3 alphanumeric characters.',
    });
  }

  if (!rawPassword || rawPassword.length < 6) {
    return res.status(400).json({
      error: 'ពាក្យសម្ងាត់ត្រូវមានយ៉ាងតិច ៦ តួអក្សរ! / Password must be at least 6 characters.',
    });
  }

  const exists =
    gameState.players.some((p) => p.username.toLowerCase() === cleanUsername.toLowerCase()) ||
    gameState.admins.some((a) => a.username.toLowerCase() === cleanUsername.toLowerCase());

  if (exists) {
    return res.status(409).json({
      error: 'ឈ្មោះអ្នកប្រើប្រាស់នេះមានរួចហើយ! / Username is already taken.',
    });
  }

  const newId = gameState.getNextPlayerId();
  const newPlayer: StoredPlayerAccount = {
    id: newId,
    username: cleanUsername,
    displayName: String(displayName || cleanUsername).trim(),
    phone: String(phone || '').trim() || '—',
    passwordHash: hashPassword(rawPassword),
    status: status === 'disabled' ? 'disabled' : 'active',
    balance: 0,
    betsCount7d: 0,
    createdAt: formatNowTimestamp(),
    lastLogin: null,
    sessionVersion: 1,
  };

  gameState.players = [newPlayer, ...gameState.players];

  gameState.addAuditLog({
    actorId: admin.id,
    actorUsername: admin.username,
    actorRole: admin.role,
    action: 'CREATE_PLAYER',
    targetId: newPlayer.id,
    targetName: newPlayer.username,
    details: `បង្កើតគណនីអ្នកលេងថ្មី: ${newPlayer.username} (${newPlayer.id}) [Status: ${newPlayer.status}]`,
    ip: req.ip || '127.0.0.1',
  });

  gameState.saveStateToDisk();

  const sanitized = gameState.sanitizePlayer(newPlayer);
  broadcast({
    type: 'PLAYER_UPDATED',
    playerId: newPlayer.id,
    player: sanitized,
    playerBalances: gameState.getPlayerBalancesMap(),
  });

  return res.status(201).json({
    success: true,
    player: sanitized,
    message: `បានបង្កើតគណនី ${newPlayer.username} ដោយជោគជ័យ!`,
  });
});

// 6. Edit Player Username (Preserves Player ID and Balance!)
app.put('/api/admin/players/:id/username', requireAdminAuth, requireAdminPermission('users.manage'), (req: Request, res: Response) => {
  const admin = (req as any).adminAccount as StoredAdminAccount;
  const { id } = req.params;
  const { newUsername } = req.body || {};
  const cleanNewUsername = String(newUsername || '').trim();

  const player = gameState.players.find((p) => p.id === id);
  if (!player) {
    return res.status(404).json({ error: 'រកមិនឃើញគណនីអ្នកលេង! / Player not found' });
  }

  if (!cleanNewUsername || cleanNewUsername.length < 3 || !/^[a-zA-Z0-9_.-]+$/.test(cleanNewUsername)) {
    return res.status(400).json({
      error: 'ឈ្មោះអ្នកប្រើប្រាស់ថ្មីមិនត្រឹមត្រូវ! / Invalid new username format.',
    });
  }

  const duplicate =
    gameState.players.some(
      (p) => p.id !== player.id && p.username.toLowerCase() === cleanNewUsername.toLowerCase()
    ) ||
    gameState.admins.some((a) => a.username.toLowerCase() === cleanNewUsername.toLowerCase());

  if (duplicate) {
    return res.status(409).json({
      error: 'ឈ្មោះអ្នកប្រើប្រាស់នេះមានអ្នកប្រើរួចហើយ! / Username already exists.',
    });
  }

  const oldUsername = player.username;
  player.username = cleanNewUsername;
  if (player.displayName === oldUsername) {
    player.displayName = cleanNewUsername;
  }

  // Synchronize username across active sessions and betting records for this playerId
  Object.values(gameState.sessions).forEach((sess) => {
    if (sess.accountId === player.id) {
      sess.username = cleanNewUsername;
    }
  });
  gameState.recentBets = gameState.recentBets.map((b) =>
    b.playerId === player.id || b.username === oldUsername
      ? { ...b, playerId: player.id, username: cleanNewUsername }
      : b
  );

  gameState.addAuditLog({
    actorId: admin.id,
    actorUsername: admin.username,
    actorRole: admin.role,
    action: 'UPDATE_USERNAME',
    targetId: player.id,
    targetName: cleanNewUsername,
    details: `ប្តូរឈ្មោះគណនី ${player.id} ពី "${oldUsername}" ទៅ "${cleanNewUsername}"`,
    ip: req.ip || '127.0.0.1',
  });

  gameState.saveStateToDisk();

  const sanitized = gameState.sanitizePlayer(player);
  broadcast({
    type: 'PLAYER_UPDATED',
    playerId: player.id,
    player: sanitized,
    playerBalances: gameState.getPlayerBalancesMap(),
  });

  return res.json({
    success: true,
    player: sanitized,
    message: `បានប្តូរឈ្មោះអ្នកប្រើប្រាស់ទៅជា "${cleanNewUsername}" ដោយជោគជ័យ!`,
  });
});

// 7. Reset / Change Player Password (Invalidates old credentials & sessions immediately, preserves balance & ID)
app.put('/api/admin/players/:id/password', requireAdminAuth, requireAdminPermission('users.manage'), (req: Request, res: Response) => {
  const admin = (req as any).adminAccount as StoredAdminAccount;
  const { id } = req.params;
  const { newPassword } = req.body || {};
  const rawNewPassword = String(newPassword || '');

  const player = gameState.players.find((p) => p.id === id);
  if (!player) {
    return res.status(404).json({ error: 'រកមិនឃើញគណនីអ្នកលេង! / Player not found' });
  }

  if (!rawNewPassword || rawNewPassword.length < 6) {
    return res.status(400).json({
      error: 'ពាក្យសម្ងាត់ថ្មីត្រូវមានយ៉ាងតិច ៦ តួអក្សរ! / Password must be at least 6 characters.',
    });
  }

  player.passwordHash = hashPassword(rawNewPassword);
  player.sessionVersion += 1;
  const revokedCount = gameState.revokeSessionsForAccount(player.id);

  gameState.addAuditLog({
    actorId: admin.id,
    actorUsername: admin.username,
    actorRole: admin.role,
    action: 'RESET_PASSWORD',
    targetId: player.id,
    targetName: player.username,
    details: `ផ្លាស់ប្តូរពាក្យសម្ងាត់ថ្មីសម្រាប់: ${player.username} (${player.id}) • Revoked ${revokedCount} session(s)`,
    ip: req.ip || '127.0.0.1',
  });

  gameState.saveStateToDisk();

  const sanitized = gameState.sanitizePlayer(player);
  broadcast({
    type: 'PLAYER_UPDATED',
    playerId: player.id,
    player: sanitized,
    playerBalances: gameState.getPlayerBalancesMap(),
  });

  return res.json({
    success: true,
    player: sanitized,
    revokedSessions: revokedCount,
    message: `បានផ្លាស់ប្តូរពាក្យសម្ងាត់ថ្មីសម្រាប់ ${player.username} ដោយជោគជ័យ!`,
  });
});

// 8. Enable / Disable Player Account
app.put('/api/admin/players/:id/status', requireAdminAuth, requireAdminPermission('users.manage'), (req: Request, res: Response) => {
  const admin = (req as any).adminAccount as StoredAdminAccount;
  const { id } = req.params;
  const { status } = req.body || {};

  const player = gameState.players.find((p) => p.id === id);
  if (!player) {
    return res.status(404).json({ error: 'រកមិនឃើញគណនីអ្នកលេង! / Player not found' });
  }

  if (status !== 'active' && status !== 'disabled') {
    return res.status(400).json({ error: 'Invalid status value' });
  }

  player.status = status;
  let revokedCount = 0;
  if (status === 'disabled') {
    player.sessionVersion += 1;
    revokedCount = gameState.revokeSessionsForAccount(player.id);
  }

  gameState.addAuditLog({
    actorId: admin.id,
    actorUsername: admin.username,
    actorRole: admin.role,
    action: status === 'active' ? 'ENABLE_PLAYER' : 'DISABLE_PLAYER',
    targetId: player.id,
    targetName: player.username,
    details: `${status === 'active' ? 'បើកដំណើរការគណនីឡើងវិញ' : 'បិទគណនី'}: ${player.username} (${player.id})`,
    ip: req.ip || '127.0.0.1',
  });

  gameState.saveStateToDisk();

  const sanitized = gameState.sanitizePlayer(player);
  broadcast({
    type: 'PLAYER_UPDATED',
    playerId: player.id,
    player: sanitized,
    playerBalances: gameState.getPlayerBalancesMap(),
  });

  return res.json({
    success: true,
    player: sanitized,
    revokedSessions: revokedCount,
    message:
      status === 'active'
        ? `គណនី ${player.username} ត្រូវបានបើកឱ្យដំណើរការឡើងវិញ!`
        : `គណនី ${player.username} ត្រូវបានបិទជាបណ្ដោះអាសន្ន!`,
  });
});

// 9. Explicitly Revoke Player Sessions
app.post('/api/admin/players/:id/revoke-sessions', requireAdminAuth, requireAdminPermission('users.manage'), (req: Request, res: Response) => {
  const admin = (req as any).adminAccount as StoredAdminAccount;
  const { id } = req.params;

  const player = gameState.players.find((p) => p.id === id);
  if (!player) {
    return res.status(404).json({ error: 'រកមិនឃើញគណនីអ្នកលេង! / Player not found' });
  }

  player.sessionVersion += 1;
  const revokedCount = gameState.revokeSessionsForAccount(player.id);

  gameState.addAuditLog({
    actorId: admin.id,
    actorUsername: admin.username,
    actorRole: admin.role,
    action: 'REVOKE_SESSIONS',
    targetId: player.id,
    targetName: player.username,
    details: `បញ្ឈប់រាល់ការចូលប្រើប្រាស់ (Revoked Sessions) សម្រាប់: ${player.username} (${player.id})`,
    ip: req.ip || '127.0.0.1',
  });

  gameState.saveStateToDisk();

  return res.json({
    success: true,
    revokedCount,
    player: gameState.sanitizePlayer(player),
    message: `បានបញ្ឈប់ការចូលប្រើប្រាស់ទាំងអស់របស់ ${player.username} ដោយជោគជ័យ!`,
  });
});

// 9b. Delete Temporary/Test Player Account (Admin with users.manage)
app.delete('/api/admin/players/:id', requireAdminAuth, requireAdminPermission('users.manage'), (req: Request, res: Response) => {
  const { id } = req.params;
  const player = gameState.players.find((p) => p.id === id);
  if (!player) {
    return res.status(404).json({ error: 'Player not found' });
  }
  gameState.revokeSessionsForAccount(player.id);
  gameState.players = gameState.players.filter((p) => p.id !== id);
  gameState.transactions = gameState.transactions.filter((t) => t.playerId !== id && t.userName !== player.username);
  gameState.auditLogs = gameState.auditLogs.filter((l) => l.targetId !== id && l.actorId !== id);
  gameState.saveStateToDisk();
  return res.json({ success: true, deletedId: id });
});

// 10. Pause / Resume Lottery Round Schedule
app.post('/api/admin/round/pause-resume', requireAdminAuth, requireAdminPermission('rounds.manage'), (req: Request, res: Response) => {
  const admin = (req as any).adminAccount as StoredAdminAccount;
  const { paused } = req.body || {};
  gameState.platformSettings.isRoundPaused =
    typeof paused === 'boolean' ? paused : !gameState.platformSettings.isRoundPaused;

  gameState.addAuditLog({
    actorId: admin.id,
    actorUsername: admin.username,
    actorRole: admin.role,
    action: gameState.platformSettings.isRoundPaused ? 'ROUND_PAUSED' : 'ROUND_RESUMED',
    targetId: `2004#${gameState.currentRoundIndex}`,
    details: gameState.platformSettings.isRoundPaused
      ? `ផ្អាកការរាប់ថយក្រោយជុំ 2004#${gameState.currentRoundIndex}`
      : `បន្តការរាប់ថយក្រោយជុំ 2004#${gameState.currentRoundIndex}`,
    ip: req.ip || '127.0.0.1',
  });

  gameState.saveStateToDisk();
  broadcast({
    type: 'TICK',
    countdown: gameState.countdown,
    currentRoundIndex: gameState.currentRoundIndex,
    isBettingClosed:
      gameState.countdown <= gameState.platformSettings.bettingLockoutSeconds ||
      gameState.platformSettings.isRoundPaused,
  });

  return res.json({
    success: true,
    isRoundPaused: gameState.platformSettings.isRoundPaused,
  });
});

// 11. Staff & Permissions Management
app.get('/api/admin/staff', requireAdminAuth, (req: Request, res: Response) => {
  return res.json({
    staff: gameState.admins.map((a) => gameState.sanitizeAdmin(a)),
  });
});

// 12. System Settings Update
app.put('/api/admin/settings', requireAdminAuth, requireAdminPermission('settings.manage'), (req: Request, res: Response) => {
  const admin = (req as any).adminAccount as StoredAdminAccount;
  const updates = req.body || {};

  if (typeof updates.roundDurationSeconds === 'number' && updates.roundDurationSeconds >= 30) {
    gameState.platformSettings.roundDurationSeconds = updates.roundDurationSeconds;
  }
  if (typeof updates.bettingLockoutSeconds === 'number' && updates.bettingLockoutSeconds >= 3) {
    gameState.platformSettings.bettingLockoutSeconds = updates.bettingLockoutSeconds;
  }
  if (typeof updates.minBetRiel === 'number' && updates.minBetRiel >= 100) {
    gameState.platformSettings.minBetRiel = updates.minBetRiel;
  }
  if (typeof updates.maxBetRiel === 'number' && updates.maxBetRiel >= 10000) {
    gameState.platformSettings.maxBetRiel = updates.maxBetRiel;
  }
  if (typeof updates.sessionTimeoutMinutes === 'number' && updates.sessionTimeoutMinutes >= 5) {
    gameState.platformSettings.sessionTimeoutMinutes = updates.sessionTimeoutMinutes;
  }
  if (typeof updates.maintenanceMode === 'boolean') {
    gameState.platformSettings.maintenanceMode = updates.maintenanceMode;
  }

  gameState.addAuditLog({
    actorId: admin.id,
    actorUsername: admin.username,
    actorRole: admin.role,
    action: 'UPDATE_SETTINGS',
    details: `បានធ្វើបច្ចុប្បន្នភាពការកំណត់ប្រព័ន្ធ (Duration: ${gameState.platformSettings.roundDurationSeconds}s, Lockout: ${gameState.platformSettings.bettingLockoutSeconds}s)`,
    ip: req.ip || '127.0.0.1',
  });

  gameState.saveStateToDisk();
  return res.json({
    success: true,
    platformSettings: gameState.platformSettings,
  });
});

// 13. Audit Logs Query
app.get('/api/admin/audit-logs', requireAdminAuth, requireAdminPermission('audit.view'), (req: Request, res: Response) => {
  const search = String(req.query.search || '').trim().toLowerCase();
  const action = String(req.query.action || 'all').toUpperCase();

  const logs = gameState.auditLogs.filter((l) => {
    const matchSearch =
      !search ||
      l.actorUsername.toLowerCase().includes(search) ||
      l.details.toLowerCase().includes(search) ||
      (l.targetName && l.targetName.toLowerCase().includes(search)) ||
      (l.targetId && l.targetId.toLowerCase().includes(search));
    const matchAction = action === 'ALL' || l.action.toUpperCase() === action;
    return matchSearch && matchAction;
  });

  return res.json({ logs });
});

// ========================================================
// EXISTING GAME & ADMIN ENDPOINTS (PRESERVED + SECURED)
// ========================================================

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: Date.now(),
    clientsConnected: wss.clients.size,
    currentRoundIndex: gameState.currentRoundIndex,
    countdown: gameState.countdown,
    forcedWinningNumber: gameState.forcedWinningNumber,
    cfRay: req.headers['cf-ray'] || null,
    cfConnectingIp: req.headers['cf-connecting-ip'] || null,
  });
});

app.get('/api/state', (req, res) => {
  const playerAuth = extractPlayerSession(req);
  res.json(gameState.getStatePayload(playerAuth?.player || null));
});

// Admin: Set Pre-determined Winning Result (Protected by requireAdminAuth + results.manage)
app.post('/api/admin/set-result', requireAdminAuth, requireAdminPermission('results.manage'), (req, res) => {
  const admin = (req as any).adminAccount as StoredAdminAccount;
  const { number } = req.body;
  gameState.forcedWinningNumber =
    typeof number === 'number' && number >= 1 && number <= 12 ? number : null;
  gameState.saveStateToDisk();

  gameState.addAuditLog({
    actorId: admin.id,
    actorUsername: admin.username,
    actorRole: admin.role,
    action: 'SET_RESULT',
    targetId: `2004#${gameState.currentRoundIndex}`,
    targetName: `Round #${gameState.currentRoundIndex}`,
    details: gameState.forcedWinningNumber
      ? `កំណត់លទ្ធផលជុំ 2004#${gameState.currentRoundIndex} = លេខ ${gameState.forcedWinningNumber} (${ANIMALS_DATA[gameState.forcedWinningNumber]?.khmerName})`
      : `កំណត់លទ្ធផលជុំ 2004#${gameState.currentRoundIndex} ទៅជាចៃដន្យ (Random)`,
    ip: req.ip || '127.0.0.1',
  });

  broadcast({
    type: 'FORCED_RESULT_UPDATED',
    forcedWinningNumber: gameState.forcedWinningNumber,
  });

  res.json({
    success: true,
    forcedWinningNumber: gameState.forcedWinningNumber,
    message: gameState.forcedWinningNumber
      ? `កំណត់លទ្ធផលឈ្នះជាមុន: លេខ ${gameState.forcedWinningNumber}`
      : 'កំណត់ឡើងវិញទៅជាចៃដន្យ',
  });
});

// Admin: Force Immediate Draw (Protected by requireAdminAuth + results.manage)
app.post('/api/admin/force-draw', requireAdminAuth, requireAdminPermission('results.manage'), (req, res) => {
  const admin = (req as any).adminAccount as StoredAdminAccount;
  const { targetNumber } = req.body;

  gameState.addAuditLog({
    actorId: admin.id,
    actorUsername: admin.username,
    actorRole: admin.role,
    action: 'FORCE_DRAW',
    targetId: `2004#${gameState.currentRoundIndex}`,
    details: `បញ្ជាចាប់ឆ្នោតភ្លាមៗសម្រាប់ជុំ 2004#${gameState.currentRoundIndex}${targetNumber ? ` (លេខ ${targetNumber})` : ''}`,
    ip: req.ip || '127.0.0.1',
  });

  executeDrawSequence(targetNumber);
  res.json({ success: true, message: 'បានចាប់ផ្តើមការចាប់ឆ្នោតភ្លាមៗលើគ្រប់ឧបករណ៍' });
});

// Admin: Add Manual Result Record to History (Protected by requireAdminAuth + results.manage)
app.post('/api/admin/manual-result', requireAdminAuth, requireAdminPermission('results.manage'), (req, res) => {
  const admin = (req as any).adminAccount as StoredAdminAccount;
  const { result } = req.body;
  if (!result || !result.number || !result.roundId) {
    return res.status(400).json({ error: 'Invalid result object' });
  }

  gameState.history = [result, ...gameState.history.filter((h) => h.roundId !== result.roundId)];
  gameState.saveStateToDisk();

  gameState.addAuditLog({
    actorId: admin.id,
    actorUsername: admin.username,
    actorRole: admin.role,
    action: 'MANUAL_RESULT',
    targetId: result.roundId,
    details: `បញ្ចូលលទ្ធផលដោយដៃ: ជុំ ${result.roundId} = លេខ ${result.number} (${result.animal})`,
    ip: req.ip || '127.0.0.1',
  });

  broadcast({
    type: 'HISTORY_UPDATED',
    history: gameState.history,
  });

  res.json({ success: true, history: gameState.history });
});

// Admin: Delete Result from History (Protected by requireAdminAuth + results.manage)
app.delete('/api/admin/result/:roundId', requireAdminAuth, requireAdminPermission('results.manage'), (req, res) => {
  const admin = (req as any).adminAccount as StoredAdminAccount;
  const { roundId } = req.params;
  gameState.history = gameState.history.filter((h) => h.roundId !== roundId);
  gameState.saveStateToDisk();

  gameState.addAuditLog({
    actorId: admin.id,
    actorUsername: admin.username,
    actorRole: admin.role,
    action: 'DELETE_RESULT',
    targetId: roundId,
    details: `លុបកំណត់ត្រាលទ្ធផលជុំ ${roundId}`,
    ip: req.ip || '127.0.0.1',
  });

  broadcast({
    type: 'HISTORY_UPDATED',
    history: gameState.history,
  });

  res.json({ success: true, history: gameState.history });
});

// Player: Place Bet (Scoped to logged-in player account if authenticated)
app.post('/api/bet', (req, res) => {
  const { betRecord } = req.body;
  if (!betRecord || !betRecord.totalStake) {
    return res.status(400).json({ error: 'Invalid bet record' });
  }

  if (
    gameState.countdown <= gameState.platformSettings.bettingLockoutSeconds ||
    gameState.isRevealing ||
    gameState.platformSettings.isRoundPaused
  ) {
    return res.status(403).json({ error: 'Betting is closed for this round' });
  }

  const playerAuth = extractPlayerSession(req);
  const activePlayer =
    playerAuth?.player ||
    (betRecord.playerId ? gameState.players.find((p) => p.id === betRecord.playerId) : undefined);

  if (activePlayer) {
    if (activePlayer.balance < betRecord.totalStake) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    activePlayer.balance -= betRecord.totalStake;
    activePlayer.betsCount7d = (activePlayer.betsCount7d || 0) + 1;
    betRecord.playerId = activePlayer.id;
    betRecord.username = activePlayer.username;
    if (activePlayer.id === 'P0001001') {
      gameState.balance = activePlayer.balance;
    }
  } else {
    if (gameState.balance < betRecord.totalStake) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    gameState.balance -= betRecord.totalStake;
    betRecord.playerId = betRecord.playerId || 'P0001001';
    betRecord.username = betRecord.username || 'player1';
  }

  const newBalance = activePlayer ? activePlayer.balance : gameState.balance;
  gameState.recentBets = [betRecord, ...gameState.recentBets];
  gameState.saveStateToDisk();

  broadcast({
    type: 'BET_PLACED',
    betRecord,
    recentBets: gameState.recentBets,
    newBalance,
    playerBalances: gameState.getPlayerBalancesMap(),
  });

  res.json({
    success: true,
    betRecord,
    newBalance,
  });
});

// Transactions: Deposit / Withdrawal Request
app.post('/api/transaction', (req, res) => {
  const { userName, userPhone, type, amount, method, status, note, playerId } = req.body;
  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Invalid transaction amount' });
  }

  const playerAuth = extractPlayerSession(req);
  const adminAuth = extractAdminSession(req);

  // If an admin is submitting an approved transaction, verify finance.manage permission
  if (adminAuth && !hasAdminPermission(adminAuth.admin, 'finance.manage')) {
    return res.status(403).json({
      error: 'គណនីអ្នកគ្រប់គ្រងនេះមិនមានសិទ្ធិ "finance.manage" ទេ! / Insufficient permissions: requires finance.manage',
      code: 'INSUFFICIENT_ADMIN_PERMISSION',
    });
  }

  // Only allow pre-approved status if request comes from an authenticated Admin with finance.manage
  const resolvedStatus = adminAuth && status === 'approved' ? 'approved' : 'pending';
  const targetPlayer =
    (playerId && gameState.players.find((p) => p.id === playerId)) ||
    (userName && gameState.players.find((p) => p.username.toLowerCase() === String(userName).toLowerCase())) ||
    playerAuth?.player;

  const timeStr = formatShortTime();
  const newTx: TransactionRecord = {
    id: `tx-${Date.now()}`,
    playerId: targetPlayer?.id || 'P0001001',
    userName: targetPlayer?.username || userName || 'player1',
    userPhone: targetPlayer?.phone || userPhone || '012 888 999',
    type: type || 'deposit',
    amount,
    method: method || 'ABA Bank',
    status: resolvedStatus,
    timestamp: Date.now(),
    timeString: timeStr,
    note: note || '',
  };

  if (newTx.status === 'approved') {
    if (targetPlayer) {
      if (newTx.type === 'deposit') {
        targetPlayer.balance += newTx.amount;
      } else if (newTx.type === 'withdrawal') {
        targetPlayer.balance = Math.max(0, targetPlayer.balance - newTx.amount);
      }
      if (targetPlayer.id === 'P0001001') {
        gameState.balance = targetPlayer.balance;
      }
    } else {
      if (newTx.type === 'deposit') {
        gameState.balance += newTx.amount;
      } else if (newTx.type === 'withdrawal') {
        gameState.balance = Math.max(0, gameState.balance - newTx.amount);
      }
    }
  }

  gameState.transactions = [newTx, ...gameState.transactions];
  if (adminAuth) {
    gameState.addAuditLog({
      actorId: adminAuth.admin.id,
      actorUsername: adminAuth.admin.username,
      actorRole: adminAuth.admin.role,
      action: 'CREATE_TRANSACTION',
      targetId: newTx.id,
      targetName: newTx.userName,
      details: `បង្កើតប្រតិបត្តិការ ${newTx.type}: ${newTx.amount.toLocaleString()}៛ សម្រាប់ ${newTx.userName}`,
      ip: req.ip || '127.0.0.1',
    });
  }
  gameState.saveStateToDisk();

  const updatedBalance = targetPlayer ? targetPlayer.balance : gameState.balance;
  broadcast({
    type: 'TRANSACTION_UPDATED',
    transactions: gameState.transactions,
    newBalance: updatedBalance,
    playerBalances: gameState.getPlayerBalancesMap(),
  });

  res.json({ success: true, transaction: newTx, newBalance: updatedBalance });
});

// Transactions: Approve / Reject Transaction (Protected by requireAdminAuth + finance.manage)
app.post('/api/transaction/:id/status', requireAdminAuth, requireAdminPermission('finance.manage'), (req, res) => {
  const admin = (req as any).adminAccount as StoredAdminAccount;
  const { id } = req.params;
  const { status } = req.body;

  const existingTx = gameState.transactions.find((t) => t.id === id);
  if (!existingTx) {
    return res.status(404).json({ error: 'Transaction not found' });
  }

  if (existingTx.status !== 'pending') {
    return res.status(400).json({ error: 'Transaction already processed' });
  }

  existingTx.status = status;

  const targetPlayer = gameState.players.find(
    (p) => p.id === existingTx.playerId || p.username.toLowerCase() === existingTx.userName.toLowerCase()
  );

  if (status === 'approved') {
    if (targetPlayer) {
      if (existingTx.type === 'deposit') {
        targetPlayer.balance += existingTx.amount;
      } else if (existingTx.type === 'withdrawal') {
        targetPlayer.balance = Math.max(0, targetPlayer.balance - existingTx.amount);
      }
      if (targetPlayer.id === 'P0001001') {
        gameState.balance = targetPlayer.balance;
      }
    } else {
      if (existingTx.type === 'deposit') {
        gameState.balance += existingTx.amount;
      } else if (existingTx.type === 'withdrawal') {
        gameState.balance = Math.max(0, gameState.balance - existingTx.amount);
      }
    }
  }

  gameState.addAuditLog({
    actorId: admin.id,
    actorUsername: admin.username,
    actorRole: admin.role,
    action: status === 'approved' ? 'APPROVE_TRANSACTION' : 'REJECT_TRANSACTION',
    targetId: existingTx.id,
    targetName: existingTx.userName,
    details: `${status === 'approved' ? 'អនុម័ត' : 'បដិសេធ'}ប្រតិបត្តិការ ${existingTx.id} (${existingTx.amount.toLocaleString()}៛) របស់ ${existingTx.userName}`,
    ip: req.ip || '127.0.0.1',
  });

  gameState.saveStateToDisk();

  broadcast({
    type: 'TRANSACTION_UPDATED',
    transactions: gameState.transactions,
    newBalance: targetPlayer ? targetPlayer.balance : gameState.balance,
    playerBalances: gameState.getPlayerBalancesMap(),
  });

  res.json({
    success: true,
    transactions: gameState.transactions,
    newBalance: targetPlayer ? targetPlayer.balance : gameState.balance,
  });
});

// Wallet: Direct Balance Update
app.post('/api/wallet/balance', (req, res) => {
  const { balance } = req.body;
  if (typeof balance === 'number') {
    const playerAuth = extractPlayerSession(req);
    if (playerAuth) {
      playerAuth.player.balance = balance;
    }
    gameState.balance = balance;
    gameState.saveStateToDisk();
    broadcast({
      type: 'BALANCE_UPDATED',
      newBalance: balance,
      playerBalances: gameState.getPlayerBalancesMap(),
    });
    return res.json({ success: true, balance });
  }
  res.status(400).json({ error: 'Invalid balance value' });
});

// Explicitly block any ZIP source download routes (HTTP 404)
app.get(['/download', '/zip', '/downloads', '/download/:id', '/downloads/:file'], (_req, res) => {
  return res.status(404).json({ error: 'ZIP download endpoints have been disabled and removed.' });
});


// ========================================================
// MULTI-PORT STARTUP (3000 Primary, 3001 Game, 5174 Admin)
// ========================================================

function attachWebSocketUpgrade(srv: http.Server) {
  srv.on('upgrade', (request, socket, head) => {
    if (request.url?.startsWith('/ws')) {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    }
  });
}

async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: false },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  const GAME_PORT = Number(process.env.PORT || process.env.GAME_PORT) || 3001;
  const gameServer = http.createServer(app);
  attachWebSocketUpgrade(gameServer);
  gameServer.listen(GAME_PORT, '0.0.0.0', () => {
    console.log(`🎮 Lottery12KH Game Page & Shared Backend listening on http://127.0.0.1:${GAME_PORT}/`);
  });
}

startServer();
