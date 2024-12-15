// SPDX-License-Identifier: GPL-3.0-only
/*
 *  Prism Launcher - Minecraft Launcher
 *  Copyright (C) 2022 Sefa Eyeoglu <contact@scrumplex.net>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 *      Copyright 2013-2021 MultiMC Contributors
 *
 *      Authors: Orochimarufan <orochimarufan.x3@gmail.com>
 *
 *      Licensed under the Apache License, Version 2.0 (the "License");
 *      you may not use this file except in compliance with the License.
 *      You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the License is distributed on an "AS IS" BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the License for the specific language governing permissions and
 *      limitations under the License.
 */

#include "MinecraftAccount.h"
#include <QColor>
#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStringList>
#include <QUuid>
#include <QDebug>
#include <QPainter>
#include "minecraft/auth/AccountData.h"
#include "minecraft/auth/AuthFlow.h"

MinecraftAccount::MinecraftAccount(QObject* parent) : QObject(parent) {
    data.internalId = QUuid::createUuid().toString().remove(QRegularExpression("[{}-]"));
}

MinecraftAccountPtr MinecraftAccount::loadFromJsonV3(const QJsonObject& json) {
    MinecraftAccountPtr account(new MinecraftAccount());
    if (account->data.resumeStateFromV3(json)) {
        return account;
    }
    return nullptr;
}

MinecraftAccountPtr MinecraftAccount::createBlankMSA() {
    MinecraftAccountPtr account(new MinecraftAccount());
    account->data.type = AccountType::MSA;
    return account;
}

MinecraftAccountPtr MinecraftAccount::createOffline(const QString& username) {
    auto account = makeShared<MinecraftAccount>();
    account->data.type = AccountType::Offline;
    account->data.yggdrasilToken.token = "0";  // No real token is needed for offline mode
    account->data.yggdrasilToken.validity = Validity::Certain;  // Assume valid token
    account->data.yggdrasilToken.issueInstant = QDateTime::currentDateTimeUtc();
    account->data.yggdrasilToken.extra["userName"] = username;
    account->data.yggdrasilToken.extra["clientToken"] = QUuid::createUuid().toString().remove(QRegularExpression("[{}-]"));
    account->data.minecraftProfile.id = uuidFromUsername(username).toString().remove(QRegularExpression("[{}-]"));
    account->data.minecraftProfile.name = username;
    account->data.minecraftProfile.validity = Validity::Certain;
    return account;
}

QJsonObject MinecraftAccount::saveToJson() const {
    return data.saveState();
}

AccountState MinecraftAccount::accountState() const {
    return data.accountState;
}

QPixmap MinecraftAccount::getFace() const {
    QPixmap skinTexture;
    if (!skinTexture.loadFromData(data.minecraftProfile.skin.data, "PNG")) {
        return QPixmap();
    }
    QPixmap skin = QPixmap(8, 8);
#if QT_VERSION >= QT_VERSION_CHECK(5, 14, 0)
    skin.fill(QColorConstants::Transparent);
#else
    skin.fill(QColor(0, 0, 0, 0));
#endif
    QPainter painter(&skin);
    painter.drawPixmap(0, 0, skinTexture.copy(8, 8, 8, 8));
    painter.drawPixmap(0, 0, skinTexture.copy(40, 8, 8, 8));
    return skin.scaled(64, 64, Qt::KeepAspectRatio);
}

shared_qobject_ptr<AuthFlow> MinecraftAccount::login(bool useDeviceCode) {
    if (data.type == AccountType::Offline) {
        // No need to perform any login for offline accounts.
        emit authSucceeded();  // Immediately succeed authentication
        return nullptr;  // No task needed
    }

    // For online accounts, continue with the authentication flow as usual
    Q_ASSERT(m_currentTask.get() == nullptr);
    m_currentTask.reset(new AuthFlow(&data, useDeviceCode ? AuthFlow::Action::DeviceCode : AuthFlow::Action::Login));
    connect(m_currentTask.get(), &Task::succeeded, this, &MinecraftAccount::authSucceeded);
    connect(m_currentTask.get(), &Task::failed, this, &MinecraftAccount::authFailed);
    connect(m_currentTask.get(), &Task::aborted, this, [this] { authFailed(tr("Aborted")); });
    emit activityChanged(true);
    return m_currentTask;
}

shared_qobject_ptr<AuthFlow> MinecraftAccount::refresh() {
    if (data.type == AccountType::Offline) {
        // No need to refresh an offline account.
        return nullptr;
    }

    // For online accounts, continue with the refresh flow
    if (m_currentTask) {
        return m_currentTask;
    }

    m_currentTask.reset(new AuthFlow(&data, AuthFlow::Action::Refresh));
    connect(m_currentTask.get(), &Task::succeeded, this, &MinecraftAccount::authSucceeded);
    connect(m_currentTask.get(), &Task::failed, this, &MinecraftAccount::authFailed);
    connect(m_currentTask.get(), &Task::aborted, this, [this] { authFailed(tr("Aborted")); });
    emit activityChanged(true);
    return m_currentTask;
}

shared_qobject_ptr<AuthFlow> MinecraftAccount::currentTask() {
    return m_currentTask;
}

void MinecraftAccount::authSucceeded() {
    m_currentTask.reset();
    emit changed();
    emit activityChanged(false);
}

void MinecraftAccount::authFailed(QString reason) {
    switch (m_currentTask->taskState()) {
        case AccountTaskState::STATE_OFFLINE:
        case AccountTaskState::STATE_DISABLED:
            // NOTE: user will need to fix this themselves.
        case AccountTaskState::STATE_FAILED_SOFT:
            // NOTE: this doesn't do much. There was an error of some sort.
            break;
        case AccountTaskState::STATE_FAILED_HARD:
            if (accountType() == AccountType::MSA) {
                data.msaToken.token = QString();
                data.msaToken.refresh_token = QString();
                data.msaToken.validity = Validity::None;
                data.validity_ = Validity::None;
            } else {
                data.yggdrasilToken.token = QString();
                data.yggdrasilToken.validity = Validity::None;
                data.validity_ = Validity::None;
            }
            emit changed();
            break;
        case AccountTaskState::STATE_FAILED_GONE:
            data.validity_ = Validity::None;
            emit changed();
            break;
        case AccountTaskState::STATE_CREATED:
        case AccountTaskState::STATE_WORKING:
        case AccountTaskState::STATE_SUCCEEDED:
            // Not reachable here, as they are not failures.
            break;
    }
    m_currentTask.reset();
    emit activityChanged(false);
}

bool MinecraftAccount::isActive() const {
    return !m_currentTask.isNull();
}

bool MinecraftAccount::shouldRefresh() const {
    /* 
     * Never refresh accounts that are being used by the game, it breaks the game session.
     * Always refresh accounts that have not been refreshed yet during this session.
     * Don't refresh broken accounts.
     * Refresh accounts that would expire in the next 12 hours (fresh token validity is 24 hours).
     */
    if (isInUse()) {
        return false;
    }
    switch (data.validity_) {
        case Validity::Certain:
            break;
        case Validity::None:
            return false;
        case Validity::Assumed:
            return true;
    }
    auto now = QDateTime::currentDateTimeUtc();
    auto issuedTimestamp = data.yggdrasilToken.issueInstant;
    auto expiresTimestamp = data.yggdrasilToken.notAfter;

    if (!expiresTimestamp.isValid()) {
        expiresTimestamp = issuedTimestamp.addSecs(24 * 3600);
    }
    if (now.secsTo(expiresTimestamp) < (12 * 3600)) {
        return true;
    }
    return false;
}

void MinecraftAccount::fillSession(AuthSessionPtr session) {
    if (ownsMinecraft() && !hasProfile()) {
        session->status = AuthSession::RequiresProfileSetup;
    } else {
        if (session->wants_online) {
            session->status = AuthSession::PlayableOnline;
        } else {
            session->status = AuthSession::PlayableOffline;
        }
    }

    // Set the access token for offline session
    session->access_token = data.accessToken();  // This is a dummy token for offline mode
    session->player_name = data.profileName();
    session->uuid = data.profileId();

    if (session->uuid.isEmpty()) {
        session->uuid = uuidFromUsername(session->player_name).toString().remove(QRegularExpression("[{}-]"));
    }
    session->user_type = typeString();
    session->session = "-";  // Offline mode doesn't require a real session token
}
