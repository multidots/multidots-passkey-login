<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use const JSON_THROW_ON_ERROR;

trait SerializerTrait
{
    protected function serialize(mixed $data): string
    {
        $serializer = (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create();

        return $serializer->serialize($data, JsonEncoder::FORMAT, [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
        ]);
    }

    protected function deserialize(string $data, string $class): mixed
    {
        $serializer = (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create();

        return $serializer->deserialize($data, $class, JsonEncoder::FORMAT);
    }
}
