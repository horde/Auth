<?php

use Rector\Config\RectorConfig;
use Rector\PHPUnit\AnnotationsToAttributes\Rector\ClassMethod\DataProviderAnnotationToAttributeRector;
use Rector\PHPUnit\Set\PHPUnitSetList;

return RectorConfig::configure()
   ->withPaths([
       __DIR__ . '/test',
   ])    ->withRules([
       DataProviderAnnotationToAttributeRector::class,
   ])
 ->withSets([
     PHPUnitSetList::PHPUNIT_100,
 ]);
