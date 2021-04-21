/*
Copyright 2014 VirusTotal S.L. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "mainwindow.h"
#include "vt_uploader_application.h"
#include <QApplication>

int main(int argc, char *argv[])
{
  //QApplication a(argc, argv);
  VTUploaderApplication a(argc, argv);
  MainWindow w;


  QObject::connect(&a, SIGNAL(loadFile(QString)),
    &w, SLOT(AddFile(QString)),  Qt::QueuedConnection);

  QObject::connect(&a, SIGNAL(loadDir(QString)),
    &w, SLOT(AddDir(QString)),  Qt::QueuedConnection);

  w.show();

  return a.exec();
}
