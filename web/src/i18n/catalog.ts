// Every interface string, written as [简体中文, 繁體中文, English]. Keeping the three together
// makes a missing translation impossible to overlook; a unit test checks every entry.
import { common } from './messages/common'
import { shell } from './messages/shell'
import { dashboard } from './messages/dashboard'
import { nodes } from './messages/nodes'
import { relays } from './messages/relays'
import { subs } from './messages/subs'
import { sources } from './messages/sources'
import { system } from './messages/system'
import { ai } from './messages/ai'
import { panel } from './messages/panel'
import { telegram } from './messages/telegram'

export type Entry = readonly [string, string, string]

export const catalog = { ...common, ...shell, ...dashboard, ...nodes, ...relays, ...subs, ...sources, ...system, ...ai, ...panel, ...telegram } as const
export type MessageKey = keyof typeof catalog
